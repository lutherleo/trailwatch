"""Baseline, risk scoring, dedup, engine and ingest tests (unit + property + integration)."""

from __future__ import annotations

import gzip
import io
import json
import math
import random
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import (
    CONSOLE_UA,
    HOSTILE_AMS_IP,
    HQ_IP,
    T0,
    console_login,
    event,
    raw,
    user_identity,
)
from trailwatch.alerts import (
    Deduplicator,
    alert_from_crossing,
    alert_from_finding,
    alert_to_dict,
    alert_to_json,
)
from trailwatch.baseline import BaselineStore, Dim, Observation, PrincipalProfile
from trailwatch.config import BaselineConfig, Config, DedupConfig, ScoringConfig
from trailwatch.engine import Detector
from trailwatch.ingest import (
    IngestStats,
    ReorderBuffer,
    delivery_sort_key,
    discover,
    iter_file,
    iter_stream,
    ordered,
    parse_records,
)
from trailwatch.model import EvidenceRef, Finding, Severity
from trailwatch.scoring import RiskScorer
from trailwatch.window import BoundedLRU

DAY = 86_400.0


def obs(t: float, api: str = "ec2:DescribeInstances", **kw: str) -> Observation:
    return Observation(
        time=t,
        api=api,
        region=kw.get("region", "us-east-1"),
        ua_family=kw.get("ua", "aws-cli"),
        asn=kw.get("asn", "AS64512"),
        country=kw.get("country", "US"),
    )


def finding(
    principal: str = "p",
    t: float = T0,
    severity: Severity = Severity.LOW,
    key: str = "k",
    rule: str = "r",
    evidence: tuple[str, ...] = ("e1",),
) -> Finding:
    return Finding(rule, severity, principal, t, f"title {key}", "detail", evidence, key, ("T1",))


# --- baseline --------------------------------------------------------------------------------


def test_profile_warmup_requires_days_and_events() -> None:
    cfg = BaselineConfig(warmup_days=7, warmup_events=10)
    profile = PrincipalProfile.new(T0, cfg)
    for i in range(10):
        profile.observe(obs(T0 + i))
    assert not profile.warmed_up(T0 + DAY, cfg)
    assert profile.warmed_up(T0 + 8 * DAY, cfg)
    assert not PrincipalProfile.new(T0, cfg).warmed_up(T0 + 30 * DAY, cfg)


def test_profile_novelty_familiarity_and_decay() -> None:
    cfg = BaselineConfig(half_life_days=1, familiar_min_weight=3)
    profile = PrincipalProfile.new(T0, cfg)
    for i in range(4):
        profile.observe(obs(T0 + i))
    assert not profile.is_new(Dim.ASN, "AS64512")
    assert profile.is_new(Dim.ASN, "AS1")
    assert profile.is_familiar(Dim.REGION, "us-east-1", T0 + 10, cfg)
    assert not profile.is_familiar(Dim.REGION, "us-east-1", T0 + 2 * DAY, cfg)


def test_profile_ignores_missing_network_fields() -> None:
    profile = PrincipalProfile.new(T0, BaselineConfig())
    profile.observe(Observation(T0, "s3:ListBuckets", "us-east-1", "boto3", None, None, ("h",)))
    assert len(profile.counters[Dim.ASN]) == 0
    assert profile.weight(Dim.HABIT, "h", T0) == 1.0


def test_recon_peak_only_reflects_previous_days() -> None:
    profile = PrincipalProfile.new(T0, BaselineConfig())
    profile.record_recon(T0, 30)
    assert profile.recon_peak == 0
    profile.record_recon(T0 + DAY, 5)
    assert profile.recon_peak == 30
    profile.record_recon(T0 + 2 * DAY, 1)
    assert profile.recon_peak == pytest.approx(30 * 0.98)


def test_baseline_store_is_lru_bounded_and_snapshots_round_trip() -> None:
    cfg = BaselineConfig(max_principals=3)
    store = BaselineStore(cfg)
    for i in range(5):
        store.observe(f"p{i}", obs(T0 + i, api=f"svc:Api{i}"))
    assert len(store) == 3
    assert store.evictions == 2
    assert store.principals() == ["p2", "p3", "p4"]
    store.get("p2")
    assert store.global_stats.api_share("svc:Api4", T0 + 5) == pytest.approx(0.2, rel=0.01)
    snapshot = json.loads(json.dumps(store.to_dict()))
    restored = BaselineStore.from_dict(snapshot, cfg)
    assert restored.principals() == store.principals()
    original = store.get("p4")
    copy = restored.get("p4")
    assert original is not None
    assert copy is not None
    assert copy.weight(Dim.API, "svc:Api4", T0 + 10) == original.weight(
        Dim.API, "svc:Api4", T0 + 10
    )
    with pytest.raises(ValueError, match="version"):
        BaselineStore.from_dict({"version": 99}, cfg)


def test_empty_population_share_is_zero() -> None:
    assert BaselineStore(BaselineConfig()).global_stats.api_share("x", T0) == 0.0


# --- scoring ---------------------------------------------------------------------------------


def test_scorer_crosses_threshold_once_and_decays() -> None:
    scorer = RiskScorer(ScoringConfig(threshold=55, half_life_hours=1), max_principals=10)
    assert scorer.add(finding(severity=Severity.MEDIUM)) is None  # 25
    assert scorer.add(finding(severity=Severity.MEDIUM, t=T0 + 1)) is None  # ~50
    crossing = scorer.add(finding(severity=Severity.LOW, t=T0 + 2))  # ~60 >= 55
    assert crossing is not None
    assert len(crossing.contributions) == 3
    assert scorer.add(finding(severity=Severity.LOW, t=T0 + 3)) is None  # already above
    assert scorer.score("p", T0 + 3 + 3600) == pytest.approx(scorer.score("p", T0 + 3) / 2)
    assert scorer.add(finding(severity=Severity.INFO)) is None
    assert scorer.score("nobody", T0) == 0.0


@settings(max_examples=60)
@given(st.lists(st.tuples(st.floats(0, 48 * 3600), st.sampled_from(list(Severity))), max_size=60))
def test_scorer_matches_brute_force_sum(hits: list[tuple[float, Severity]]) -> None:
    cfg = ScoringConfig(half_life_hours=6, max_contributions=8)
    scorer = RiskScorer(cfg, max_principals=4)
    hits = sorted(hits, key=lambda h: h[0])
    for when, severity in hits:
        scorer.add(finding(t=T0 + when, severity=severity))
    if hits:
        now = T0 + hits[-1][0]
        expected = sum(
            cfg.weight(s) * math.pow(0.5, (now - (T0 + w)) / (6 * 3600)) for w, s in hits
        )
        assert scorer.score("p", now) == pytest.approx(expected, rel=1e-9, abs=1e-9)


def test_scorer_bounds_contributions_and_principals() -> None:
    scorer = RiskScorer(ScoringConfig(max_contributions=3, threshold=1000), max_principals=2)
    for i in range(10):
        scorer.add(finding(principal=f"p{i % 3}", t=T0 + i, severity=Severity.HIGH))
    assert len(scorer) == 2


# --- alerts and dedup ------------------------------------------------------------------------


def index_with(*ids: str) -> BoundedLRU[str, EvidenceRef]:
    index: BoundedLRU[str, EvidenceRef] = BoundedLRU(100)
    for i, eid in enumerate(ids):
        index.put(eid, EvidenceRef(eid, T0 + i, "ec2:X", HQ_IP, "us-east-1"))
    return index


def test_rule_alert_shape_and_json() -> None:
    alert = alert_from_finding(
        finding(severity=Severity.HIGH, evidence=("e1", "e2")), "1", 50.0, index_with("e1")
    )
    data = alert_to_dict(alert)
    assert data["kind"] == "rule"
    assert data["severity"] == "high"
    assert [e["event_id"] for e in data["evidence"]] == ["e1"]
    assert data["findings"][0]["evidence"] == ["e1", "e2"]
    assert alert.alert_id.startswith("tw-")
    assert json.loads(alert_to_json(alert)) == data
    assert alert.evidence_ids() == {"e1", "e2"}


def test_dedup_merges_repeats_then_reopens_after_ttl() -> None:
    dedup = Deduplicator(DedupConfig(ttl_hours=1, max_evidence=3))
    index = index_with("e1", "e2", "e3", "e4", "e5")
    first = alert_from_finding(finding(severity=Severity.HIGH), "1", 0, index)
    assert dedup.offer(first) is first
    for i in range(4):
        dup = alert_from_finding(
            finding(severity=Severity.HIGH, t=T0 + 60 * (i + 1), evidence=(f"e{i + 2}",)),
            "1",
            0,
            index,
        )
        assert dedup.offer(dup) is None
    assert first.count == 5
    assert len(first.evidence) == 3
    assert len(first.findings) == 3
    assert dedup.suppressed == 4
    later = alert_from_finding(finding(severity=Severity.HIGH, t=T0 + 3 * 3600), "1", 0, index)
    assert dedup.offer(later) is later


def test_dedup_escalates_on_higher_severity() -> None:
    dedup = Deduplicator(DedupConfig())
    index = index_with("e1")
    low = alert_from_finding(finding(severity=Severity.HIGH), "1", 0, index)
    high = alert_from_finding(finding(severity=Severity.CRITICAL, t=T0 + 5), "1", 0, index)
    assert dedup.offer(low) is low
    assert dedup.offer(high) is high
    assert dedup.escalated == 1
    assert len(dedup) == 1


def test_risk_alert_folds_into_open_rule_alert_for_same_principal() -> None:
    from trailwatch.scoring import Crossing

    dedup = Deduplicator(DedupConfig())
    index = index_with("e1", "e9")
    rule_alert = alert_from_finding(finding(severity=Severity.CRITICAL), "1", 0, index)
    dedup.offer(rule_alert)
    crossing = Crossing("p", T0 + 10, 70.0, (finding(t=T0 + 10, key="z", evidence=("e9",)),))
    risk = alert_from_crossing(crossing, "1", 60.0, index)
    assert risk.severity is Severity.MEDIUM
    assert "risk 70 >= 60" in risk.summary
    assert dedup.offer(risk) is None
    assert "e9" in rule_alert.evidence_ids()
    other = alert_from_crossing(Crossing("q", T0, 130.0, (finding("q"),)), "1", 60.0, index)
    assert other.severity is Severity.HIGH
    assert dedup.offer(other) is other


# --- engine ----------------------------------------------------------------------------------


def test_engine_end_to_end_privilege_escalation_sequence() -> None:
    detector = Detector(Config())
    events = [
        console_login("legacy", t=T0, ip=HOSTILE_AMS_IP),
        event(
            "CreateUser",
            "iam",
            t=T0 + 60,
            ua=CONSOLE_UA,
            ip=HOSTILE_AMS_IP,
            identity=user_identity("legacy", mfa=False),
            params={"userName": "bd"},
            read_only=False,
        ),
        event(
            "CreateAccessKey",
            "iam",
            t=T0 + 120,
            ua=CONSOLE_UA,
            ip=HOSTILE_AMS_IP,
            identity=user_identity("legacy", mfa=False),
            params={"userName": "bd"},
            read_only=False,
        ),
        event(
            "StopLogging",
            "cloudtrail",
            t=T0 + 180,
            ip=HOSTILE_AMS_IP,
            identity=user_identity("legacy"),
            params={"name": "org-trail"},
            read_only=False,
        ),
    ]
    alerts = list(detector.run(events))
    rules = [a.rule_id for a in alerts]
    # Both IAM changes hang off the same no-MFA login, so the second folds into the first.
    assert rules == ["console_no_mfa_iam_change", "unusual_access_key_creation", "logging_disabled"]
    assert alerts[0].count >= 2  # second IAM change, plus the folded-in risk crossing
    assert all(a.severity >= Severity.HIGH for a in alerts)
    assert detector.stats.events == 4
    assert detector.stats.alerts == 3
    assert detector.dedup.suppressed >= 1
    sizes = detector.state_sizes()
    assert sizes["baseline_principals"] == 1
    assert sizes["evidence_index"] == 4


def test_engine_skips_aws_service_events() -> None:
    detector = Detector(Config())
    record = raw(identity={"type": "AWSService", "invokedBy": "config.amazonaws.com"})
    from trailwatch.parse import parse_record

    assert detector.process(parse_record(record)) == []
    assert detector.stats.skipped_service_events == 1
    assert len(detector.baseline) == 0


def test_engine_state_stays_bounded_under_many_principals() -> None:
    config = Config().with_overrides(
        {
            "baseline.max_principals": 50,
            "state.max_rule_principals": 40,
            "dedup.max_entries": 30,
        }
    )
    detector = Detector(config)
    rng = random.Random(7)
    ips = [HQ_IP, HOSTILE_AMS_IP, "100.71.0.1", "100.75.0.1"]
    for i in range(3000):
        user = f"u{rng.randrange(400)}"
        name = rng.choice(["DescribeInstances", "CreateAccessKey", "StopLogging", "ListUsers"])
        detector.process(
            event(
                name,
                "iam",
                t=T0 + i * 5,
                ip=rng.choice(ips),
                identity=user_identity(user),
                params={"userName": "x", "name": "t"},
            )
        )
    sizes = detector.state_sizes()
    assert sizes["baseline_principals"] <= 50
    assert sizes["risk_principals"] <= 40
    assert sizes["dedup_open"] <= 30
    assert all(v <= 40 for k, v in sizes.items() if k.startswith("rule:"))


# --- ingest ----------------------------------------------------------------------------------


def test_reorder_buffer_restores_order_within_lateness() -> None:
    rng = random.Random(1)
    times = sorted(T0 + rng.uniform(0, 10_000) for _ in range(500))
    shuffled = sorted((t + rng.uniform(0, 300), t) for t in times)
    events = [event(t=t) for _, t in shuffled]
    stats = IngestStats()
    out = list(ordered(events, ReorderBuffer(max_lateness=300, max_items=10_000, stats=stats)))
    assert [e.time for e in out] == sorted(e.time for e in events)
    assert stats.late == 0
    assert stats.forced == 0


@settings(max_examples=40)
@given(st.lists(st.integers(0, 5000), max_size=150), st.integers(1, 20), st.floats(0, 600))
def test_reorder_buffer_is_bounded_and_loses_nothing(
    offsets: list[int], cap: int, lateness: float
) -> None:
    buffer = ReorderBuffer(max_lateness=lateness, max_items=cap)
    out = []
    for off in offsets:
        out.extend(buffer.push(event(t=T0 + off)))
        assert len(buffer) <= cap
    out.extend(buffer.flush())
    assert sorted(e.time for e in out) == sorted(T0 + o for o in offsets)


def test_reorder_buffer_counts_late_and_forced() -> None:
    stats = IngestStats()
    buffer = ReorderBuffer(max_lateness=10, max_items=2, stats=stats)
    buffer.push(event(t=T0))
    buffer.push(event(t=T0 + 100))  # releases T0
    buffer.push(event(t=T0 - 50))  # late
    buffer.push(event(t=T0 + 101))
    buffer.push(event(t=T0 + 102))  # over capacity -> forced
    assert stats.late == 1
    assert stats.forced >= 1
    with pytest.raises(ValueError, match="max_lateness"):
        ReorderBuffer(-1, 1)


def test_parse_records_skips_malformed_and_duplicates() -> None:
    good = raw()
    stats = IngestStats()
    events = list(parse_records([good, {"bad": 1}, dict(good), raw()], stats))
    assert len(events) == 2
    assert (stats.records, stats.malformed, stats.duplicates, stats.events) == (4, 1, 1, 2)


def test_file_formats(tmp_path: Path) -> None:
    records = [raw(), raw(), raw()]
    trail = tmp_path / "AWSLogs" / "1" / "CloudTrail" / "us-east-1"
    trail.mkdir(parents=True)
    with gzip.open(trail / "1_CloudTrail_us-east-1_20260302T0905Z_x.json.gz", "wt") as h:
        json.dump({"Records": records[:1]}, h)
    (tmp_path / "list.json").write_text(json.dumps(records[1:2]))
    (tmp_path / "lines.jsonl").write_text(json.dumps(records[2]) + "\n\nnot json\n")
    (tmp_path / "concat.json").write_text(json.dumps(raw()) + "\n" + json.dumps(raw()) + "\n")
    (tmp_path / "notes.txt").write_text("ignored")
    stats = IngestStats()
    files = discover([tmp_path])
    assert len(files) == 4
    got = [r for f in files for r in iter_file(f, stats)]
    assert len(got) == 5
    assert stats.malformed == 1
    assert stats.files == 4
    with pytest.raises(FileNotFoundError):
        discover([tmp_path / "missing"])
    assert discover([tmp_path / "list.json"]) == [tmp_path / "list.json"]


def test_unreadable_files_are_counted_and_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    good = tmp_path / "good.jsonl"
    good.write_text(json.dumps(raw()) + "\n")
    not_gzip = tmp_path / "1_CloudTrail_us-east-1_20260302T1200Z_bad.json.gz"
    not_gzip.write_bytes(b"this is not gzip data")
    payload = gzip.compress(json.dumps({"Records": [raw(), raw()]}).encode())
    truncated = tmp_path / "truncated.json.gz"
    truncated.write_bytes(payload[: len(payload) // 2])
    corrupt = tmp_path / "corrupt.json.gz"
    corrupt.write_bytes(payload[:10] + bytes(b ^ 0xFF for b in payload[10:-8]) + payload[-8:])
    latin1 = tmp_path / "latin1.jsonl"
    latin1.write_bytes(b'{"eventName": "caf\xe9"}\n')
    # One readable record, then a non-UTF-8 tail: the record read before the failure is kept.
    tail = tmp_path / "tail.jsonl"
    tail.write_bytes("".join(json.dumps(raw()) + "\n" for _ in range(3000)).encode())
    with tail.open("ab") as handle:
        handle.write(b"\xff\xfe\n")
    stats = IngestStats()
    with caplog.at_level("ERROR", logger="trailwatch.ingest"):
        got = {
            f.name: len(list(iter_file(f, stats)))
            for f in [not_gzip, truncated, corrupt, latin1, good, tail]
        }
    assert stats.files == 6
    assert stats.bad_files == 5
    assert got["good.jsonl"] == 1
    assert got[not_gzip.name] == got["latin1.jsonl"] == 0
    assert 0 < got["tail.jsonl"] < 3000
    assert caplog.text.count("skipping unreadable file") == 5
    assert "BadGzipFile" in caplog.text
    assert "EOFError" in caplog.text
    assert "UnicodeDecodeError" in caplog.text


def test_delivery_sort_key_interleaves_regions() -> None:
    a = Path(
        "AWSLogs/1/CloudTrail/us-west-2/2026/03/02/1_CloudTrail_us-west-2_20260302T0900Z_a.json.gz"
    )
    b = Path(
        "AWSLogs/1/CloudTrail/eu-west-1/2026/03/02/1_CloudTrail_eu-west-1_20260302T0905Z_b.json.gz"
    )
    c = Path(
        "AWSLogs/1/CloudTrail/us-east-1/2026/03/02/1_CloudTrail_us-east-1_20260302T0910Z_c.json.gz"
    )
    assert sorted([c, b, a], key=delivery_sort_key) == [a, b, c]
    assert delivery_sort_key(Path("x.jsonl")) == ("", "x.jsonl")


def test_iter_stream_accepts_records_and_log_objects() -> None:
    lines = "\n".join([json.dumps(raw()), json.dumps({"Records": [raw(), raw()]}), "{broken"])
    stats = IngestStats()
    assert len(list(iter_stream(io.StringIO(lines), stats))) == 3
    assert stats.malformed == 1
