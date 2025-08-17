"""Rules-as-code tests: audit logging and detection tampering."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import Harness, event
from trailwatch.config import Config
from trailwatch.model import Severity
from trailwatch.rules import LoggingTamperRule


def check(
    name: str,
    source: str,
    params: dict[str, Any] | None = None,
    config: Config | None = None,
    error: str | None = None,
) -> list[tuple[Severity, str]]:
    h = Harness(config)
    rule = LoggingTamperRule(h.config)
    ev = event(name, source, params=params, read_only=False, error=error)
    return [(f.severity, f.detail) for f in rule.evaluate(h.ctx(ev))]


@pytest.mark.parametrize(
    ("name", "source", "params", "severity"),
    [
        ("StopLogging", "cloudtrail", {"name": "org-trail"}, Severity.CRITICAL),
        ("DeleteTrail", "cloudtrail", {"name": "org-trail"}, Severity.CRITICAL),
        ("UpdateTrail", "cloudtrail", {"name": "t", "isMultiRegionTrail": False}, Severity.HIGH),
        (
            "UpdateTrail",
            "cloudtrail",
            {"name": "t", "includeGlobalServiceEvents": "false"},
            Severity.HIGH,
        ),
        ("UpdateTrail", "cloudtrail", {"name": "t", "s3BucketName": "elsewhere"}, Severity.MEDIUM),
        (
            "PutEventSelectors",
            "cloudtrail",
            {"trailName": "t", "eventSelectors": [{"includeManagementEvents": False}]},
            Severity.HIGH,
        ),
        (
            "PutEventSelectors",
            "cloudtrail",
            {"trailName": "t", "eventSelectors": [{"readWriteType": "ReadOnly"}]},
            Severity.HIGH,
        ),
        ("DeleteDetector", "guardduty", {"detectorId": "abc"}, Severity.CRITICAL),
        ("UpdateDetector", "guardduty", {"detectorId": "abc", "enable": False}, Severity.HIGH),
        ("DisassociateFromAdministratorAccount", "guardduty", {}, Severity.HIGH),
        ("StopConfigurationRecorder", "config", {"configurationRecorderName": "d"}, Severity.HIGH),
        ("DeleteConfigurationRecorder", "config", {}, Severity.HIGH),
        ("DeleteDeliveryChannel", "config", {}, Severity.HIGH),
        ("DeleteFlowLogs", "ec2", {"flowLogIds": ["fl-1"]}, Severity.MEDIUM),
    ],
)
def test_tampering_actions(
    name: str, source: str, params: dict[str, Any], severity: Severity
) -> None:
    findings = check(name, source, params)
    assert [s for s, _ in findings] == [severity]


@pytest.mark.parametrize(
    ("name", "source", "params"),
    [
        ("UpdateTrail", "cloudtrail", {"name": "t", "enableLogFileValidation": True}),
        (
            "PutEventSelectors",
            "cloudtrail",
            {"trailName": "t", "eventSelectors": [{"readWriteType": "All"}]},
        ),
        ("PutEventSelectors", "cloudtrail", {"trailName": "t", "eventSelectors": ["junk"]}),
        ("UpdateDetector", "guardduty", {"detectorId": "abc", "enable": True}),
        ("DescribeTrails", "cloudtrail", None),
        ("StartLogging", "cloudtrail", {"name": "t"}),
    ],
)
def test_benign_configuration_changes(
    name: str, source: str, params: dict[str, Any] | None
) -> None:
    assert check(name, source, params) == []


def test_failed_attempt_is_downgraded_and_labelled() -> None:
    findings = check("StopLogging", "cloudtrail", {"name": "org"}, error="AccessDenied")
    assert findings[0][0] == Severity.HIGH
    assert findings[0][1].startswith("attempted (AccessDenied)")


def test_allowlisted_trail_prefix_is_ignored() -> None:
    config = Config().with_overrides({"logging_tamper.allowlist_trail_prefixes": ["sandbox-"]})
    arn = "arn:aws:cloudtrail:us-west-2:111122223333:trail/sandbox-trail-7"
    assert check("DeleteTrail", "cloudtrail", {"name": arn}, config) == []
    assert check("DeleteTrail", "cloudtrail", {"name": "org-trail"}, config)


def test_guardduty_findings_use_guardduty_technique() -> None:
    h = Harness()
    finding = LoggingTamperRule(h.config).evaluate(
        h.ctx(event("DeleteDetector", "guardduty", params={"detectorId": "d"}))
    )[0]
    assert finding.techniques == ("T1562.001",)
    assert finding.dedup_key == "DeleteDetector:d"


def test_disabled_rule() -> None:
    config = Config().with_overrides({"logging_tamper.enabled": False})
    assert check("StopLogging", "cloudtrail", {"name": "x"}, config) == []
