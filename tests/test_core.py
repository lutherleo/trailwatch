"""Unit and property tests for parsing, bounded state, network map, UA families and config."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import T0, event, raw, user_identity
from trailwatch.config import Config, ConfigError, parse_override, to_mapping
from trailwatch.model import Alert, Severity, format_time
from trailwatch.netmap import NetInfo, NetMap, NetMapError, haversine_km
from trailwatch.parse import (
    ParseError,
    console_login_used_mfa,
    parse_identity,
    parse_record,
    parse_time,
)
from trailwatch.useragent import classify
from trailwatch.window import BoundedLRU, DecayedCounter, TimeWindow, decay_factor

# --- parsing ---------------------------------------------------------------------------------


def test_parse_iam_user_record() -> None:
    ev = parse_record(raw("CreateUser", "iam", params={"userName": "x"}, read_only=False))
    assert ev.api == "iam:CreateUser"
    assert ev.service == "iam"
    assert ev.principal == "arn:aws:iam::111122223333:user/alice"
    assert ev.identity.user_name == "alice"
    assert ev.read_only is False
    assert ev.iso_time == format_time(T0)
    assert not ev.failed


def test_parse_assumed_role_uses_role_arn_as_principal() -> None:
    ident = parse_identity(user_identity("deployer", kind="AssumedRole"))
    assert ident.principal_key == "arn:aws:iam::111122223333:role/deployer"
    assert ident.session_name == "session-1"


def test_parse_assumed_role_without_issuer_derives_role_arn() -> None:
    ident = parse_identity(
        {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/App/i-0abc"}
    )
    assert ident.principal_key == "arn:aws:iam::123456789012:role/App"
    assert ident.user_name == "App"


def test_sso_sessions_get_per_person_principals() -> None:
    ident = parse_identity(
        {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::1:assumed-role/AWSReservedSSO_Dev_1a/dev-07",
            "accountId": "1",
            "sessionContext": {
                "sessionIssuer": {
                    "arn": "arn:aws:iam::1:role/AWSReservedSSO_Dev_1a",
                    "userName": "AWSReservedSSO_Dev_1a",
                },
                "attributes": {"mfaAuthenticated": "false"},
            },
        }
    )
    assert ident.principal_key == "arn:aws:iam::1:role/AWSReservedSSO_Dev_1a/dev-07"
    assert ident.mfa_authenticated is False


@pytest.mark.parametrize(
    ("identity", "expected"),
    [
        ({"type": "Root", "accountId": "9"}, "arn:aws:iam::9:root"),
        (
            {"type": "AWSService", "invokedBy": "config.amazonaws.com"},
            "service:config.amazonaws.com",
        ),
        ({"type": "IAMUser", "accountId": "9", "userName": "bob"}, "arn:aws:iam::9:user/bob"),
        ({"type": "IAMUser", "accountId": "9", "principalId": "AIDA1"}, "iam-user:9:AIDA1"),
        (
            {"type": "FederatedUser", "arn": "arn:aws:sts::9:federated-user/x"},
            "arn:aws:sts::9:federated-user/x",
        ),
        ({"type": "AWSAccount", "accountId": "9", "principalId": "P"}, "awsaccount:9:P"),
        ({"type": "AssumedRole"}, "assumed-role:unknown"),
    ],
)
def test_principal_keys(identity: dict[str, Any], expected: str) -> None:
    assert parse_identity(identity).principal_key == expected


@pytest.mark.parametrize(
    "mutation",
    [
        {"eventName": None},
        {"eventSource": ""},
        {"eventID": None},
        {"eventTime": "yesterday"},
        {"eventTime": "2026-01-01T00:00:00"},
        {"eventTime": 12345},
        {"userIdentity": "root"},
    ],
)
def test_parse_errors(mutation: dict[str, Any]) -> None:
    record = raw()
    record.update(mutation)
    with pytest.raises(ParseError):
        parse_record(record)


def test_parse_rejects_non_objects_and_tolerates_odd_fields() -> None:
    with pytest.raises(ParseError):
        parse_record(["not", "a", "record"])
    record = raw(extra={"readOnly": "true", "requestParameters": "garbage", "awsRegion": None})
    ev = parse_record(record)
    assert ev.read_only is True
    assert ev.request_parameters == {}
    assert ev.region == "unknown"
    assert parse_record(raw(extra={"readOnly": 7})).read_only is None
    assert parse_record(raw(extra={"eventName": 42})).name == "42"


def test_parse_time_accepts_offsets() -> None:
    assert parse_time("2026-03-02T09:00:00Z") == T0
    assert parse_time("2026-03-02T10:00:00+01:00") == T0


def test_console_mfa_field() -> None:
    record = raw("ConsoleLogin", "signin", extra={"additionalEventData": {"MFAUsed": "Yes"}})
    assert console_login_used_mfa(parse_record(record)) is True
    assert console_login_used_mfa(event()) is None


# --- model -----------------------------------------------------------------------------------


def test_severity_parse_bump_and_label() -> None:
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.CRITICAL.bump(3) is Severity.CRITICAL
    assert Severity.INFO.bump(-1) is Severity.INFO
    assert Severity.LOW.label == "low"
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("catastrophic")


def test_alert_last_seen_defaults_to_created() -> None:
    alert = Alert("a", "rule", "r", Severity.LOW, "p", "1", 5.0, "t", "s", 0.0, [], [], [])
    assert alert.last_seen == 5.0
    assert alert.evidence_ids() == set()


# --- bounded state ---------------------------------------------------------------------------


def test_bounded_lru_evicts_least_recently_used() -> None:
    lru: BoundedLRU[str, int] = BoundedLRU(2)
    lru.put("a", 1)
    lru.put("b", 2)
    assert lru.get("a") == 1  # refresh a
    lru.put("c", 3)
    assert "b" not in lru
    assert lru.keys() == ["a", "c"]
    assert lru.evictions == 1
    assert lru.peek("a") == 1
    assert lru.pop("a") == 1
    assert lru.get_or_create("d", lambda: 4) == 4
    assert dict(lru.items()) == {"c": 3, "d": 4}
    with pytest.raises(ValueError, match="capacity"):
        BoundedLRU(0)


@given(st.lists(st.tuples(st.integers(0, 50), st.integers()), max_size=300), st.integers(1, 10))
def test_bounded_lru_never_exceeds_capacity(ops: list[tuple[int, int]], cap: int) -> None:
    lru: BoundedLRU[int, int] = BoundedLRU(cap)
    for key, value in ops:
        lru.put(key, value)
        assert len(lru) <= cap
    if ops:
        assert lru.peek(ops[-1][0]) == ops[-1][1]


def test_time_window_expiry_and_distinct() -> None:
    win: TimeWindow[str] = TimeWindow(span=60, max_items=100)
    for i, item in enumerate(["a", "b", "a", "c"]):
        win.add(i * 10.0, item)
    assert win.distinct() == 3
    assert win.count("a") == 2
    assert win.oldest() == 0.0
    win.expire(65.0)  # drops the "a" at t=0
    assert win.keys() == {"a", "b", "c"}
    assert win.count("a") == 1
    win.expire(75.0)  # drops "b" at t=10
    assert win.keys() == {"a", "c"}
    win.expire(1000.0)
    assert len(win) == 0
    assert win.oldest() is None
    win.add(1.0, "z")
    win.clear()
    assert win.distinct() == 0
    with pytest.raises(ValueError, match="span"):
        TimeWindow(0, 1)
    with pytest.raises(ValueError, match="max_items"):
        TimeWindow(1, 0)


@given(
    st.lists(st.tuples(st.floats(0, 1000), st.sampled_from("abcdefgh")), max_size=200),
    st.integers(1, 20),
)
def test_time_window_matches_brute_force(items: list[tuple[float, str]], cap: int) -> None:
    items = sorted(items)
    win: TimeWindow[str] = TimeWindow(span=50, max_items=cap)
    kept: list[tuple[float, str]] = []
    for when, item in items:
        win.add(when, item)
        kept = [(t, i) for t, i in [*kept, (when, item)] if t >= when - 50][-cap:]
        assert len(win) == len(kept) <= cap
        assert win.distinct() == len({i for _, i in kept})


def test_decayed_counter_halves_after_half_life() -> None:
    counter = DecayedCounter(half_life=10, capacity=4)
    counter.add("a", 0)
    assert counter.weight("a", 10) == pytest.approx(0.5)
    assert counter.total(20) == pytest.approx(0.25)
    assert counter.weight("missing", 0) == 0.0
    assert decay_factor(-5, 10) == 1.0
    restored = DecayedCounter.from_dict(counter.to_dict())
    assert restored.weight("a", 10) == pytest.approx(0.5)
    with pytest.raises(ValueError, match="half_life"):
        DecayedCounter(0, 1)
    with pytest.raises(ValueError, match="capacity"):
        DecayedCounter(1, 0)


@settings(max_examples=50)
@given(st.lists(st.tuples(st.sampled_from("abcdefghijkl"), st.floats(0, 100)), max_size=120))
def test_decayed_counter_bounded_and_exact(adds: list[tuple[str, float]]) -> None:
    adds = sorted(adds, key=lambda x: x[1])
    counter = DecayedCounter(half_life=25, capacity=5)
    for key, when in adds:
        counter.add(key, when)
        assert len(counter) <= 5
    if adds:
        now = adds[-1][1]
        expected_total = sum(math.pow(0.5, (now - t) / 25) for _, t in adds)
        assert counter.total(now) == pytest.approx(expected_total, rel=1e-9)
        # The highest-weight key always survives pruning and its weight is exact.
        by_key: dict[str, float] = {}
        for key, when in adds:
            by_key[key] = by_key.get(key, 0.0) + math.pow(0.5, (now - when) / 25)
        top = max(by_key, key=lambda k: by_key[k])
        if counter.pruned == 0:
            assert counter.weight(top, now) == pytest.approx(by_key[top], rel=1e-9)
        assert top in counter


# --- network map -----------------------------------------------------------------------------


def test_bundled_netmap_lookups() -> None:
    netmap = NetMap.bundled()
    info = netmap.lookup("100.64.200.1")
    assert info is not None
    assert (info.asn, info.city, info.kind) == (64512, "Seattle", "corporate")
    assert info.asn_label == "AS64512"
    assert netmap.lookup("100.64.200.1") is info  # cached
    assert netmap.lookup("8.8.8.8") is None
    assert netmap.lookup("ec2.amazonaws.com") is None
    assert netmap.lookup("2001:db8::1") is None
    assert len(netmap) >= 30
    assert netmap.by_asn(64550)[0].country == "NL"


def test_netmap_ipv6_and_errors(tmp_path: Path) -> None:
    v6 = NetInfo("2001:db8::/32", 65000, "Doc", "isp", "ZZ", "Nowhere", 0.0, 0.0)
    netmap = NetMap([v6])
    assert netmap.lookup("2001:db8::5") == v6
    assert netmap.lookup("10.0.0.1") is None
    with pytest.raises(NetMapError, match="overlapping"):
        NetMap([v6, NetInfo("2001:db8:1::/48", 1, "x", "isp", "ZZ", "c", 0, 0)])
    with pytest.raises(NetMapError, match="invalid CIDR"):
        NetMap([NetInfo("10.0.0.1/8", 1, "x", "isp", "ZZ", "c", 0, 0)])
    bad_header = tmp_path / "bad.csv"
    bad_header.write_text("cidr,asn\n10.0.0.0/8,1\n")
    with pytest.raises(NetMapError, match="header"):
        NetMap.from_csv(bad_header)
    bad_row = tmp_path / "row.csv"
    bad_row.write_text(
        "# comment\ncidr,asn,org,kind,country,city,lat,lon\n10.0.0.0/8,x,o,k,c,c,1,2\n"
    )
    with pytest.raises(NetMapError, match="bad row"):
        NetMap.from_csv(bad_row)
    good = tmp_path / "good.csv"
    good.write_text("cidr,asn,org,kind,country,city,lat,lon\n10.0.0.0/8,1,o,isp,ZZ,c,1,2\n")
    assert NetMap.from_csv(good).lookup("10.1.2.3") is not None


def test_haversine_known_distances() -> None:
    assert haversine_km(0, 0, 0, 0) == 0
    # Seattle -> Amsterdam is roughly 7,850 km.
    assert 7700 < haversine_km(47.6062, -122.3321, 52.3676, 4.9041) < 8000
    assert haversine_km(0, 0, 0, 180) == pytest.approx(math.pi * 6371.0088, rel=1e-6)


# --- user agents -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ua", "family"),
    [
        ("aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0 botocore/2.0", "aws-cli"),
        ("Boto3/1.34.69 md/Botocore#1.34.69", "boto3"),
        ("APN/1.0 HashiCorp/1.0 Terraform/1.7.5 aws-sdk-go-v2/1.26.0", "terraform"),
        ("aws-sdk-java/1.12.680 Linux/5.10", "aws-sdk-java"),
        ("aws-sdk-go-v2/1.26.0 os/linux", "aws-sdk-go"),
        ("aws-sdk-nodejs/2.1 linux", "aws-sdk-js"),
        ("AWSPowerShell/4.1.500", "powershell"),
        ("console.ec2.amazonaws.com", "console"),
        ("signin.amazonaws.com", "console"),
        ("AWS Internal", "aws-internal"),
        ("cloudformation.amazonaws.com", "aws-service"),
        ("python-requests/2.31.0", "scripted-http"),
        ("curl/8.4.0", "scripted-http"),
        ("Mozilla/5.0 (X11; Linux x86_64)", "browser"),
        ("aws-cli/1.32 Python/3.11 Linux/6.6.9-amd64-kali botocore/1.34", "offensive-distro"),
        ("", "unknown"),
        ("something else", "unknown"),
    ],
)
def test_user_agent_families(ua: str, family: str) -> None:
    assert classify(ua) == family


# --- configuration ---------------------------------------------------------------------------


def test_config_defaults_round_trip_through_mapping() -> None:
    config = Config()
    assert Config.from_mapping(to_mapping(config)) == config


def test_config_load_and_overrides(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text('[scoring]\nthreshold = 75\ndirect_alert_severity = "critical"\n')
    config = Config.load(path)
    assert config.scoring.threshold == 75.0
    assert config.scoring.direct_alert_severity is Severity.CRITICAL
    changed = config.with_overrides({"travel.max_speed_kmh": 800, "novelty.sensitive_apis": ["a"]})
    assert changed.travel.max_speed_kmh == 800.0
    assert changed.novelty.sensitive_apis == ("a",)
    assert config.scoring.weight(Severity.MEDIUM) == 25.0


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[scoring]\nthreshhold = 1\n", "unknown config key"),
        ("[bogus]\n", "unknown config key"),
        ("[scoring]\nthreshold = 'high'\n", "expected a number"),
        ("[scoring]\nmax_contributions = 1.5\n", "expected an integer"),
        ("[baseline]\nsuppress_familiar = 1\n", "expected true/false"),
        ("[travel]\nseverity = 'nope'\n", "unknown severity"),
        ("[travel]\nseverity = 3\n", "expected a severity"),
        ("[novelty]\nsensitive_apis = 'x'\n", "list of strings"),
        ("scoring = 3\n", "expected a table"),
        ("[scoring]\nthreshold = -1\n", "must be > 0"),
        ("[baseline]\nwarmup_days = -1\n", "warmup"),
        ("[novelty]\nglobal_rare_share = 2.0\n", "global_rare_share"),
        ("[enumeration]\npeak_margin = 0.5\n", "peak_margin"),
        ("not toml [", "invalid TOML"),
    ],
)
def test_config_errors(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "c.toml"
    path.write_text(text)
    with pytest.raises(ConfigError, match=message):
        Config.load(path)


def test_config_missing_file_and_bad_override(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        Config.load(tmp_path / "missing.toml")
    with pytest.raises(ConfigError, match="unknown config key"):
        Config().with_overrides({"scoring": 1})
    with pytest.raises(ConfigError, match=r"section\.key=value"):
        parse_override("novalue")
    assert parse_override("scoring.threshold=70") == ("scoring.threshold", 70)
    assert parse_override("travel.severity=high") == ("travel.severity", "high")
    assert parse_override("baseline.suppress_familiar=false") == (
        "baseline.suppress_familiar",
        False,
    )


def test_committed_default_config_matches_builtin_defaults() -> None:
    path = Path(__file__).resolve().parents[1] / "config" / "default.toml"
    assert Config.load(path) == Config()
