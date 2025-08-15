"""Defense evasion: disabling or weakening audit logging and threat detection."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from trailwatch.model import Event, Finding, Severity
from trailwatch.rules.base import EventContext, Rule

GUARDDUTY_TECHNIQUE = ("T1562.001",)


def _false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.lower() == "false")


def _update_trail(params: Mapping[str, Any]) -> tuple[Severity, str] | None:
    if _false(params.get("isMultiRegionTrail")):
        return Severity.HIGH, "trail switched to single-region"
    if _false(params.get("includeGlobalServiceEvents")):
        return Severity.HIGH, "global service events (IAM, STS) excluded"
    if params.get("s3BucketName"):
        return Severity.MEDIUM, f"log destination changed to bucket {params['s3BucketName']}"
    return None


def _event_selectors(params: Mapping[str, Any]) -> tuple[Severity, str] | None:
    selectors = params.get("eventSelectors")
    if isinstance(selectors, list) and selectors:
        for selector in selectors:
            if not isinstance(selector, Mapping):
                continue
            if _false(selector.get("includeManagementEvents")):
                return Severity.HIGH, "management events excluded from the trail"
            if selector.get("readWriteType") not in (None, "All"):
                return Severity.HIGH, f"only {selector.get('readWriteType')} events recorded"
    return None


def _guardduty_update(params: Mapping[str, Any]) -> tuple[Severity, str] | None:
    if _false(params.get("enable")):
        return Severity.HIGH, "GuardDuty detector disabled"
    return None


def _fixed(severity: Severity, why: str) -> Callable[[Mapping[str, Any]], tuple[Severity, str]]:
    return lambda _params: (severity, why)


# (eventSource, eventName) -> classifier(requestParameters) -> (severity, reason) | None
CLASSIFIERS: dict[tuple[str, str], Callable[[Mapping[str, Any]], tuple[Severity, str] | None]] = {
    ("cloudtrail.amazonaws.com", "StopLogging"): _fixed(Severity.CRITICAL, "trail logging stopped"),
    ("cloudtrail.amazonaws.com", "DeleteTrail"): _fixed(Severity.CRITICAL, "trail deleted"),
    ("cloudtrail.amazonaws.com", "UpdateTrail"): _update_trail,
    ("cloudtrail.amazonaws.com", "PutEventSelectors"): _event_selectors,
    ("guardduty.amazonaws.com", "DeleteDetector"): _fixed(
        Severity.CRITICAL, "GuardDuty detector deleted"
    ),
    ("guardduty.amazonaws.com", "UpdateDetector"): _guardduty_update,
    ("guardduty.amazonaws.com", "DisassociateFromAdministratorAccount"): _fixed(
        Severity.HIGH, "GuardDuty member detached from administrator"
    ),
    ("config.amazonaws.com", "StopConfigurationRecorder"): _fixed(
        Severity.HIGH, "AWS Config recorder stopped"
    ),
    ("config.amazonaws.com", "DeleteConfigurationRecorder"): _fixed(
        Severity.HIGH, "AWS Config recorder deleted"
    ),
    ("config.amazonaws.com", "DeleteDeliveryChannel"): _fixed(
        Severity.HIGH, "AWS Config delivery channel deleted"
    ),
    ("ec2.amazonaws.com", "DeleteFlowLogs"): _fixed(Severity.MEDIUM, "VPC flow logs deleted"),
}


def _target(event: Event) -> str:
    params = event.request_parameters
    for key in ("name", "trailName", "detectorId", "configurationRecorderName", "flowLogIds"):
        value = params.get(key)
        if value:
            return str(value)
    return event.region


class LoggingTamperRule(Rule):
    rule_id = "logging_disabled"
    description = (
        "CloudTrail StopLogging/DeleteTrail (critical), trail or event-selector weakening, "
        "GuardDuty detector deletion/disablement, AWS Config recorder stops and VPC flow-log "
        "deletion. Trails whose name starts with an allowlisted prefix are ignored; failed "
        "attempts are one level lower."
    )
    techniques = ("T1562.008",)

    def evaluate(self, ctx: EventContext) -> list[Finding]:
        cfg = self.config.logging_tamper
        event = ctx.event
        classifier = CLASSIFIERS.get((event.source, event.name))
        if not cfg.enabled or classifier is None:
            return []
        verdict = classifier(event.request_parameters)
        if verdict is None:
            return []
        severity, reason = verdict
        target = _target(event)
        trail_name = target.rsplit("/", 1)[-1] if event.service == "cloudtrail" else ""
        allow = cfg.allowlist_trail_prefixes
        if trail_name and allow and trail_name.startswith(allow):
            return []
        if event.failed:
            severity = severity.bump(-1)
            reason = f"attempted ({event.error_code}): {reason}"
        techniques = GUARDDUTY_TECHNIQUE if event.service == "guardduty" else self.techniques
        return [
            self.finding(
                ctx,
                severity,
                f"Audit/detection tampering: {event.name}",
                f"{reason} (target {target})",
                dedup_key=f"{event.name}:{target}",
                attrs={"target": target},
                techniques=techniques,
            )
        ]
