"""Golden test: the hand-authored CloudTrail fixture must produce exactly the committed alerts.

Regenerate after an intentional behaviour change with::

    UPDATE_GOLDEN=1 uv run pytest tests/test_golden.py
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from trailwatch.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "cloudtrail"
GOLDEN = ROOT / "fixtures" / "expected-alerts.jsonl"


def test_fixture_alerts_match_golden(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "alerts.jsonl"
    assert main(["detect", str(FIXTURE_DIR), "--out", str(out), "--stats"]) == 0
    stats = json.loads(capsys.readouterr().err)
    assert stats["ingest"]["malformed"] == 1
    assert stats["ingest"]["duplicates"] == 1
    assert stats["engine"]["skipped_service_events"] == 1
    produced = out.read_text(encoding="utf-8")
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN.write_text(produced, encoding="utf-8")
    assert produced == GOLDEN.read_text(encoding="utf-8")


def test_golden_covers_the_intended_story() -> None:
    alerts = [json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines()]
    by_rule = {(a["rule_id"], a["principal"].rsplit("/", 1)[-1]): a for a in alerts}
    assert ("console_no_mfa_iam_change", "ops-legacy") in by_rule
    assert ("unusual_access_key_creation", "ops-legacy") in by_rule
    assert ("logging_disabled", "svc-backup-42") in by_rule
    assert by_rule[("logging_disabled", "svc-backup-42")]["severity"] == "critical"
    # The SSO console sign-in (MFAUsed=No by design of federation) must not alert.
    assert not any("AWSReservedSSO" in a["principal"] for a in alerts)
    # Streamed alerts are written when first emitted, so `count` reflects folding up to that
    # moment (here: the risk crossing folded into the rule alert for the same event).
    assert by_rule[("console_no_mfa_iam_change", "ops-legacy")]["count"] == 2


def test_unreadable_files_do_not_abort_a_directory_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A corrupt .gz sorted before the fixture and a non-UTF-8 file after it are skipped."""
    tree = tmp_path / "trail"
    tree.mkdir()
    src = next(FIXTURE_DIR.iterdir())
    (tree / src.name).write_bytes(src.read_bytes())
    (tree / "111122223333_CloudTrail_us-east-1_20260302T1000Z_bad.json.gz").write_bytes(b"junk")
    (tree / "111122223333_CloudTrail_us-east-1_20260302T1200Z_bad.jsonl").write_bytes(b"\xff\n")
    out = tmp_path / "alerts.jsonl"
    state = tmp_path / "state.json"
    argv = ["detect", str(tree), "--out", str(out), "--state-out", str(state), "--stats"]
    assert main(argv) == 0
    stats = json.loads(capsys.readouterr().err)
    assert stats["ingest"]["files"] == 3
    assert stats["ingest"]["bad_files"] == 2
    assert out.read_text(encoding="utf-8") == GOLDEN.read_text(encoding="utf-8")
    assert json.loads(state.read_text(encoding="utf-8"))

    # Non-UTF-8 bytes on stdin stop the read but still flush buffered events and write state.
    # Repeat the (deduplicated) log object so the bad byte lands beyond the first decode chunk.
    line = json.dumps(json.loads(src.read_text(encoding="utf-8"))) + "\n"
    data = (line * 10).encode() + b"\xff\n"
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    monkeypatch.setattr("sys.stdin", stdin)
    state.unlink()
    assert main(["detect", "-", "--state-out", str(state), "--stats"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.err)["ingest"]["bad_files"] == 1
    assert captured.out == GOLDEN.read_text(encoding="utf-8")
    assert state.exists()
