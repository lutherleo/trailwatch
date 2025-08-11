"""The detection pipeline: enrich -> rules -> baseline update -> risk scoring -> dedup -> alerts.

Per event the work is O(R + log N) for R rules and an N-row network map, with every stateful
component bounded, so the engine runs over unbounded streams in constant memory.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from trailwatch.alerts import Deduplicator, alert_from_crossing, alert_from_finding
from trailwatch.baseline import BaselineStore, Observation
from trailwatch.config import Config
from trailwatch.model import Alert, Event, EvidenceRef, Finding
from trailwatch.netmap import NetMap
from trailwatch.rules import EventContext, Rule, default_rules
from trailwatch.scoring import RiskScorer
from trailwatch.useragent import classify
from trailwatch.window import BoundedLRU

log = logging.getLogger(__name__)

EVIDENCE_INDEX_SIZE = 200_000


@dataclass(slots=True)
class EngineStats:
    events: int = 0
    skipped_service_events: int = 0
    findings: int = 0
    alerts: int = 0
    findings_by_rule: Counter[str] = field(default_factory=Counter)
    alerts_by_rule: Counter[str] = field(default_factory=Counter)
    first_time: float | None = None
    last_time: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "skipped_service_events": self.skipped_service_events,
            "findings": self.findings,
            "alerts": self.alerts,
            "findings_by_rule": dict(sorted(self.findings_by_rule.items())),
            "alerts_by_rule": dict(sorted(self.alerts_by_rule.items())),
        }


class Detector:
    """Stateful CloudTrail detector. Feed events in (approximate) time order."""

    def __init__(
        self,
        config: Config | None = None,
        netmap: NetMap | None = None,
        rules: list[Rule] | None = None,
        baseline: BaselineStore | None = None,
    ) -> None:
        self.config = config or Config()
        self.netmap = netmap if netmap is not None else NetMap.bundled()
        self.rules = rules if rules is not None else default_rules(self.config)
        self.baseline = baseline if baseline is not None else BaselineStore(self.config.baseline)
        self.scorer = RiskScorer(self.config.scoring, self.config.state.max_rule_principals)
        self.dedup = Deduplicator(self.config.dedup)
        self._evidence: BoundedLRU[str, EvidenceRef] = BoundedLRU(EVIDENCE_INDEX_SIZE)
        self.stats = EngineStats()

    def process(self, event: Event) -> list[Alert]:
        """Run one event through the pipeline and return any newly emitted alerts."""
        stats = self.stats
        stats.events += 1
        if stats.first_time is None:
            stats.first_time = event.time
        stats.last_time = event.time
        if event.identity.is_service:
            stats.skipped_service_events += 1
            return []
        cfg = self.config
        net = self.netmap.lookup(event.source_ip)
        profile = self.baseline.get(event.principal)
        ctx = EventContext(
            event=event,
            net=net,
            ua_family=classify(event.user_agent),
            profile=profile,
            baseline=self.baseline,
            config=cfg,
            warmed_up=profile is not None and profile.warmed_up(event.time, cfg.baseline),
        )
        self._evidence.put(
            event.event_id,
            EvidenceRef(event.event_id, event.time, event.api, event.source_ip, event.region),
        )
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(ctx))
        self.baseline.observe(
            event.principal,
            Observation(
                time=event.time,
                api=event.api,
                region=event.region,
                ua_family=ctx.ua_family,
                asn=ctx.asn,
                country=net.country if net else None,
                habits=tuple(ctx.habits),
            ),
        )
        return self._alerts_for(findings, event.identity.account_id or event.recipient_account_id)

    def _alerts_for(self, findings: list[Finding], account_id: str) -> list[Alert]:
        emitted: list[Alert] = []
        scoring = self.config.scoring
        for finding in findings:
            self.stats.findings += 1
            self.stats.findings_by_rule[finding.rule_id] += 1
            crossing = self.scorer.add(finding)
            candidates: list[Alert] = []
            if finding.severity >= scoring.direct_alert_severity:
                score = self.scorer.score(finding.principal, finding.time)
                candidates.append(alert_from_finding(finding, account_id, score, self._evidence))
            if crossing is not None:
                candidates.append(
                    alert_from_crossing(crossing, account_id, scoring.threshold, self._evidence)
                )
            for candidate in candidates:
                alert = self.dedup.offer(candidate)
                if alert is not None:
                    self.stats.alerts += 1
                    self.stats.alerts_by_rule[alert.rule_id] += 1
                    log.debug("alert %s %s %s", alert.alert_id, alert.rule_id, alert.principal)
                    emitted.append(alert)
        return emitted

    def run(self, events: Iterable[Event]) -> Iterator[Alert]:
        for event in events:
            yield from self.process(event)

    def state_sizes(self) -> dict[str, int]:
        """Current size of every bounded state table (used by bound tests and ``--stats``)."""
        sizes = {
            "baseline_principals": len(self.baseline),
            "risk_principals": len(self.scorer),
            "dedup_open": len(self.dedup),
            "evidence_index": len(self._evidence),
        }
        for rule in self.rules:
            sizes[f"rule:{rule.rule_id}"] = rule.state_size()
        return sizes
