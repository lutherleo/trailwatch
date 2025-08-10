"""Alert construction, deduplication and JSON serialisation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from trailwatch.config import DedupConfig
from trailwatch.model import Alert, EvidenceRef, Finding, Severity, format_time
from trailwatch.scoring import Crossing
from trailwatch.window import BoundedLRU

DedupKey = tuple[str, str, str, str]


def _alert_id(*parts: object) -> str:
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()
    return f"tw-{digest[:16]}"


def _techniques(findings: Iterable[Finding]) -> list[str]:
    return sorted({t for f in findings for t in f.techniques})


def _evidence(
    findings: Iterable[Finding], index: BoundedLRU[str, EvidenceRef]
) -> list[EvidenceRef]:
    refs: dict[str, EvidenceRef] = {}
    for finding in findings:
        for event_id in finding.evidence:
            ref = index.peek(event_id)
            if ref is not None:
                refs[event_id] = ref
    return sorted(refs.values(), key=lambda r: (r.time, r.event_id))


def alert_from_finding(
    finding: Finding, account_id: str, risk_score: float, index: BoundedLRU[str, EvidenceRef]
) -> Alert:
    """A direct ("rule") alert for one severe finding."""
    return Alert(
        alert_id=_alert_id(
            "rule", finding.rule_id, finding.principal, finding.time, finding.dedup_key
        ),
        kind="rule",
        rule_id=finding.rule_id,
        severity=finding.severity,
        principal=finding.principal,
        account_id=account_id,
        created=finding.time,
        title=finding.title,
        summary=finding.detail,
        risk_score=round(risk_score, 1),
        techniques=list(finding.techniques),
        findings=[finding],
        evidence=_evidence([finding], index),
    )


def alert_from_crossing(
    crossing: Crossing, account_id: str, threshold: float, index: BoundedLRU[str, EvidenceRef]
) -> Alert:
    """A risk alert: several findings whose decayed weights summed past the threshold."""
    findings = list(crossing.contributions)
    severity = Severity.HIGH if crossing.score >= 2 * threshold else Severity.MEDIUM
    titles: list[str] = []
    for finding in findings:
        if finding.title not in titles:
            titles.append(finding.title)
    summary = f"risk {crossing.score:.0f} >= {threshold:.0f} from {len(findings)} findings: " + (
        "; ".join(titles[-6:])
    )
    return Alert(
        alert_id=_alert_id("risk", crossing.principal, crossing.time),
        kind="risk",
        rule_id="risk_threshold",
        severity=severity,
        principal=crossing.principal,
        account_id=account_id,
        created=crossing.time,
        title=f"Elevated risk for {crossing.principal.rsplit(':', 1)[-1]}",
        summary=summary,
        risk_score=round(crossing.score, 1),
        techniques=_techniques(findings),
        findings=findings,
        evidence=_evidence(findings, index),
    )


class Deduplicator:
    """Suppress repeats of an open alert; escalate when severity rises.

    Rule alerts are keyed by ``(rule_id, principal, finding.dedup_key)``; risk alerts by
    principal. An alert stays open while repeats keep arriving within ``ttl_hours`` of its
    ``last_seen``. A risk alert for a principal that already has an open alert of equal or
    higher severity is folded into that alert instead of being emitted. Both tables are LRU
    bounded by ``max_entries``.
    """

    def __init__(self, cfg: DedupConfig) -> None:
        self.cfg = cfg
        self.ttl = cfg.ttl_hours * 3600.0
        self._open: BoundedLRU[DedupKey, Alert] = BoundedLRU(cfg.max_entries)
        self._latest: BoundedLRU[str, Alert] = BoundedLRU(cfg.max_entries)
        self.suppressed = 0
        self.escalated = 0

    def __len__(self) -> int:
        return len(self._open)

    @staticmethod
    def key_for(alert: Alert) -> DedupKey:
        dedup = alert.findings[0].dedup_key if alert.kind == "rule" and alert.findings else ""
        return (alert.kind, alert.rule_id, alert.principal, dedup)

    def _live(self, alert: Alert | None, now: float) -> bool:
        return alert is not None and now - alert.last_seen <= self.ttl

    def offer(self, alert: Alert) -> Alert | None:
        """Return ``alert`` if it should be emitted, or ``None`` if it was folded into another."""
        key = self.key_for(alert)
        existing = self._open.get(key)
        if alert.kind == "risk" and not self._live(existing, alert.created):
            latest = self._latest.get(alert.principal)
            if (
                latest is not None
                and self._live(latest, alert.created)
                and latest.severity >= alert.severity
            ):
                existing = latest
        if existing is not None and self._live(existing, alert.created):
            if alert.severity > existing.severity:
                self.escalated += 1
            else:
                self._merge(existing, alert)
                self.suppressed += 1
                return None
        self._open.put(key, alert)
        self._latest.put(alert.principal, alert)
        return alert

    def _merge(self, target: Alert, dup: Alert) -> None:
        target.count += 1
        target.last_seen = max(target.last_seen, dup.created)
        target.risk_score = max(target.risk_score, dup.risk_score)
        known_findings = {(f.rule_id, f.time, f.dedup_key) for f in target.findings}
        for finding in dup.findings:
            if (finding.rule_id, finding.time, finding.dedup_key) not in known_findings:
                target.findings.append(finding)
        del target.findings[: max(0, len(target.findings) - self.cfg.max_evidence)]
        known = {ref.event_id for ref in target.evidence}
        target.evidence.extend(ref for ref in dup.evidence if ref.event_id not in known)
        del target.evidence[: max(0, len(target.evidence) - self.cfg.max_evidence)]
        target.techniques = sorted(set(target.techniques) | set(dup.techniques))


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.label,
        "time": format_time(finding.time),
        "title": finding.title,
        "detail": finding.detail,
        "evidence": list(finding.evidence),
        "techniques": list(finding.techniques),
        "attrs": dict(finding.attrs),
    }


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    """Stable JSON shape for an alert (documented in README "Alert format")."""
    return {
        "alert_id": alert.alert_id,
        "kind": alert.kind,
        "rule_id": alert.rule_id,
        "severity": alert.severity.label,
        "principal": alert.principal,
        "account_id": alert.account_id,
        "created": format_time(alert.created),
        "last_seen": format_time(alert.last_seen),
        "count": alert.count,
        "risk_score": alert.risk_score,
        "title": alert.title,
        "summary": alert.summary,
        "techniques": alert.techniques,
        "findings": [finding_to_dict(f) for f in alert.findings],
        "evidence": [
            {
                "event_id": ref.event_id,
                "time": format_time(ref.time),
                "api": ref.api,
                "source_ip": ref.source_ip,
                "region": ref.region,
            }
            for ref in alert.evidence
        ],
    }


def alert_to_json(alert: Alert) -> str:
    return json.dumps(alert_to_dict(alert), sort_keys=True, separators=(",", ":"))
