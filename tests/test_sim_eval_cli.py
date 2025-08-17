"""Simulator, evaluation and CLI integration tests."""

from __future__ import annotations

import gzip
import io
import json
import random
from collections import Counter
from pathlib import Path

import pytest

from trailwatch.cli import dump_toml, main
from trailwatch.config import Config
from trailwatch.evaluation import (
    markdown_table,
    parse_seeds,
    run_seed,
    scenario_table,
    score_files,
    summarize,
    tune,
)
from trailwatch.parse import parse_record
from trailwatch.sim import SCENARIOS, SimConfig, Simulation, SimulationError, delivered

SHORT = SimConfig(seed=5, days=28, incidents_per_scenario=1, incident_start_day=14)


@pytest.fixture(scope="module")
def short_stream() -> list[tuple[dict[str, object], str | None]]:
    return list(Simulation(SHORT).stream())


def test_stream_is_time_ordered_and_parseable(
    short_stream: list[tuple[dict[str, object], str | None]],
) -> None:
    times = [str(r["eventTime"]) for r, _ in short_stream]
    assert times == sorted(times)
    events = [parse_record(r) for r, _ in short_stream]
    assert len({e.event_id for e in events}) == len(events)
    principals = {e.principal for e in events}
    assert len(principals) >= 18


def test_labels_cover_every_incident_event(
    short_stream: list[tuple[dict[str, object], str | None]],
) -> None:
    sim = Simulation(SHORT)
    list(sim.stream())
    labelled = Counter(label for _, label in short_stream if label)
    assert len(sim.incidents) == len(SCENARIOS)
    for incident in sim.incidents:
        assert labelled[incident.incident_id] == incident.events > 0
        assert incident.start <= incident.end
        assert incident.principal.startswith("arn:aws:iam::111122223333:")
    assert {i.scenario for i in sim.incidents} == set(SCENARIOS)


def test_simulation_is_deterministic_and_incidents_do_not_perturb_benign_traffic(
    short_stream: list[tuple[dict[str, object], str | None]],
) -> None:
    again = list(Simulation(SHORT).stream())
    assert again == short_stream
    quiet = list(Simulation(SimConfig(seed=5, days=28, incidents_per_scenario=0)).stream())
    benign = [r for r, label in short_stream if label is None]
    assert [r["eventID"] for r, _ in quiet] == [r["eventID"] for r in benign]
    other = list(Simulation(SimConfig(seed=6, days=28, incidents_per_scenario=0)).stream())
    assert [r["eventID"] for r, _ in other[:50]] != [r["eventID"] for r, _ in quiet[:50]]


def test_benign_population_has_the_intended_hard_negatives(
    short_stream: list[tuple[dict[str, object], str | None]],
) -> None:
    benign = [parse_record(r) for r, label in short_stream if label is None]
    sso_logins = [e for e in benign if e.name == "ConsoleLogin" and "AWSReservedSSO" in e.principal]
    assert sso_logins
    assert all(e.additional_event_data["MFAUsed"] == "No" for e in sso_logins)
    no_mfa = [e for e in benign if e.name == "ConsoleLogin" and "legacy" in e.principal]
    assert no_mfa
    scanner = [e for e in benign if "posture-scanner" in e.principal]
    assert len({e.api for e in scanner}) > 40
    assert any(e.source_ip.startswith("192.0.2.") for e in benign)  # unmapped networks
    assert any(e.identity.type == "AWSService" for e in benign)


def test_delivery_jitter_is_bounded(
    short_stream: list[tuple[dict[str, object], str | None]],
) -> None:
    from trailwatch.parse import parse_time

    out = list(delivered(short_stream[:3000], 300.0, random.Random(1)))
    assert sorted(id(r) for r, _ in out) == sorted(id(r) for r, _ in short_stream[:3000])
    high_water = float("-inf")
    for record, _ in out:
        t = parse_time(record["eventTime"])
        assert t >= high_water - 300.0
        high_water = max(high_water, t)
    assert [r for r, _ in out] != [r for r, _ in short_stream[:3000]]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"days": 1},
        {"incidents_per_scenario": -1},
        {"days": 10, "incident_start_day": 20},
        {"scenarios": ("nope",)},
    ],
)
def test_sim_config_validation(kwargs: dict[str, object]) -> None:
    with pytest.raises(SimulationError):
        SimConfig(**kwargs)  # type: ignore[arg-type]
    with pytest.raises(SimulationError, match="start date"):
        _ = SimConfig(start="not-a-date").start_epoch


def test_run_seed_scores_detection() -> None:
    result = run_seed(5, 28, Config(), incidents_per_scenario=1)
    assert result.incidents == len(SCENARIOS)
    assert result.detected >= 4
    assert result.true_alerts >= result.detected - 1
    assert result.alerts >= result.true_alerts
    assert all(s >= 0 for s in result.detect_seconds)
    summary = summarize([result])
    assert 0 < summary.recall <= 1
    assert 0 < summary.precision <= 1
    assert summary.events_per_second > 0
    table = markdown_table({"full": summary})
    assert "| full |" in table
    assert "stolen_access_key" in scenario_table(summary)
    with pytest.raises(ValueError, match="no results"):
        summarize([])


def test_tune_returns_all_tied_best() -> None:
    best, rows = tune([5], 21, Config(), {"scoring.threshold": [60.0, 1e9]}, 10.0)
    assert len(rows) == 2
    assert best
    assert all(b in rows for b in best)
    strict, _ = tune([5], 21, Config(), {"scoring.threshold": [60.0]}, -1.0)
    assert len(strict) == 1


def test_parse_seeds() -> None:
    assert parse_seeds("1-3") == [1, 2, 3]
    assert parse_seeds("1,5, 9") == [1, 5, 9]
    assert parse_seeds("1-2,7") == [1, 2, 7]
    for bad in ("", "3-1", "x", "1-y"):
        with pytest.raises(ValueError, match="seed"):
            parse_seeds(bad)


# --- CLI -------------------------------------------------------------------------------------


def test_cli_simulate_detect_score_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "ds"
    args = ["simulate", "--out", str(data), "--seed", "5", "--days", "28"]
    args += ["--incidents-per-scenario", "1", "--incident-start-day", "14"]
    assert main(args) == 0
    assert "incidents" in capsys.readouterr().out
    alerts = tmp_path / "alerts.jsonl"
    state = tmp_path / "state.json"
    detect = ["detect", str(data / "events.jsonl"), "--out", str(alerts), "--state-out", str(state)]
    assert main(detect) == 0
    lines = alerts.read_text().splitlines()
    assert lines
    assert all(json.loads(line)["alert_id"].startswith("tw-") for line in lines)
    assert json.loads(state.read_text())["version"] == 1
    assert main(["score", "--alerts", str(alerts), "--dataset", str(data)]) == 0
    scored = json.loads(capsys.readouterr().out)
    assert scored["detected"] >= 4
    direct = score_files(alerts, data / "labels.jsonl", data / "incidents.json")
    assert direct == scored
    resumed = tmp_path / "resumed.jsonl"
    assert main(
        [
            "detect",
            str(data),
            "--out",
            str(resumed),
            "--state-in",
            str(state),
            "--min-severity",
            "critical",
            "--fail-on",
            "high",
        ]
    ) in (0, 3)


def test_cli_cloudtrail_tree_and_stdin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "trail"
    assert (
        main(
            [
                "simulate",
                "--out",
                str(data),
                "--days",
                "3",
                "--format",
                "cloudtrail",
                "--incidents-per-scenario",
                "0",
            ]
        )
        == 0
    )
    files = sorted(data.rglob("*.json.gz"))
    assert files
    with gzip.open(files[0], "rt") as handle:
        assert "Records" in json.load(handle)
    capsys.readouterr()
    assert main(["detect", str(data / "AWSLogs"), "--stats"]) == 0
    stats = json.loads(capsys.readouterr().err)
    assert stats["ingest"]["files"] == len(files)
    line = json.dumps({"Records": [{}]})
    monkeypatch.setattr("sys.stdin", io.StringIO(line + "\n"))
    assert main(["detect", "-", "--stats"]) == 0
    assert json.loads(capsys.readouterr().err)["ingest"]["malformed"] == 1


def test_cli_fail_on_and_min_severity(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "cloudtrail"
    out = tmp_path / "a.jsonl"
    assert main(["detect", str(fixture), "--out", str(out), "--fail-on", "critical"]) == 3
    assert main(["detect", str(fixture), "--out", str(out), "--min-severity", "critical"]) == 0
    severities = {json.loads(line)["severity"] for line in out.read_text().splitlines()}
    assert severities == {"critical"}


def test_cli_eval_tune_rules_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "eval.json"
    assert (
        main(
            [
                "eval",
                "--seeds",
                "5",
                "--days",
                "21",
                "--incidents-per-scenario",
                "1",
                "--json",
                str(out),
                "--set",
                "scoring.threshold=60",
            ]
        )
        == 0
    )
    payload = json.loads(out.read_text())
    assert payload["variants"]["full"]["incidents"] == len(SCENARIOS)
    assert main(["tune", "--seeds", "5", "--days", "21", "--grid", "scoring.threshold=60,90"]) == 0
    assert "tied" in capsys.readouterr().out
    assert main(["rules"]) == 0
    assert "impossible_travel" in capsys.readouterr().out
    assert main(["config", "--set", "scoring.threshold=70"]) == 0
    text = capsys.readouterr().out
    assert "threshold = 70.0" in text
    config_file = tmp_path / "c.toml"
    config_file.write_text(dump_toml(Config()))
    assert main(["config", "--config", str(config_file)]) == 0


def test_cli_eval_ablations_runs_every_variant(tmp_path: Path) -> None:
    out = tmp_path / "eval.json"
    assert (
        main(
            [
                "eval",
                "--seeds",
                "5",
                "--days",
                "21",
                "--incidents-per-scenario",
                "1",
                "--ablations",
                "--json",
                str(out),
            ]
        )
        == 0
    )
    variants = json.loads(out.read_text())["variants"]
    assert set(variants) == {
        "full",
        "no_familiarity_suppression",
        "no_behavioral_novelty",
        "no_risk_scoring",
    }


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["detect", "/nonexistent/path"], 1),
        (["detect", "-", "--set", "nonsense"], 2),
        (["detect", "-", "--set", "scoring.bogus=1"], 2),
        (["simulate", "--out", "x", "--days", "1"], 2),
        (["tune", "--grid", "scoring.threshold"], 2),
        (["eval", "--seeds", "9-1"], 2),
        (["detect", "-", "--min-severity", "loud"], 2),
    ],
)
def test_cli_errors_exit_codes(argv: list[str], code: int) -> None:
    assert main(argv) == code


def test_cli_os_errors_exit_one(tmp_path: Path) -> None:
    assert main(["score", "--alerts", str(tmp_path / "none"), "--dataset", str(tmp_path)]) == 1
