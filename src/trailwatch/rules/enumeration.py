"""Enumeration bursts: many distinct discovery APIs across services, or many access denials."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from trailwatch.config import Config
from trailwatch.model import Event, Finding, Severity
from trailwatch.rules.base import EventContext, Rule
from trailwatch.window import BoundedLRU, TimeWindow

RECON_PREFIXES = ("List", "Describe", "Get", "Search", "Lookup")
DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation",
        "UnauthorizedAccess",
    }
)


def is_recon(event: Event) -> bool:
    return event.name.startswith(RECON_PREFIXES) and event.read_only is not False


@dataclass(slots=True)
class _Burst:
    apis: TimeWindow[str]
    services: TimeWindow[str]
    denied: TimeWindow[str]
    recent_ids: deque[str] = field(default_factory=lambda: deque(maxlen=20))
    last_fired: float = float("-inf")
    last_severity: Severity = Severity.INFO


class EnumerationBurstRule(Rule):
    rule_id = "enumeration_burst"
    description = (
        "Within enumeration.window_minutes: >= min_distinct_apis distinct discovery APIs across "
        ">= min_services services, or >= min_denied access-denied errors. Volume-only bursts "
        "are suppressed when they do not exceed peak_margin x the principal's historical daily "
        "peak (scanners and auditors); fires once per window per principal unless severity rises."
    )
    techniques = ("T1580", "T1526", "T1087.004")

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._bursts: BoundedLRU[str, _Burst] = BoundedLRU(config.state.max_rule_principals)

    def state_size(self) -> int:
        return len(self._bursts)

    def _new_burst(self) -> _Burst:
        cfg = self.config.enumeration
        span = cfg.window_minutes * 60
        return _Burst(
            apis=TimeWindow(span, cfg.max_window_items),
            services=TimeWindow(span, cfg.max_window_items),
            denied=TimeWindow(span, cfg.max_window_items),
        )

    def evaluate(self, ctx: EventContext) -> list[Finding]:
        cfg = self.config.enumeration
        event = ctx.event
        denied = event.error_code in DENIED_CODES
        if not cfg.enabled or not (is_recon(event) or denied):
            return []
        burst = self._bursts.get_or_create(ctx.principal, self._new_burst)
        burst.recent_ids.append(event.event_id)
        if is_recon(event):
            burst.apis.add(ctx.now, event.api)
            burst.services.add(ctx.now, event.service)
        else:
            burst.apis.expire(ctx.now)
            burst.services.expire(ctx.now)
        if denied:
            burst.denied.add(ctx.now, event.event_id)
        else:
            burst.denied.expire(ctx.now)

        distinct = burst.apis.distinct()
        services = burst.services.distinct()
        denials = len(burst.denied)
        profile = ctx.baseline.profile(ctx.principal, ctx.now)
        historical_peak = profile.recon_peak
        profile.record_recon(ctx.now, distinct)

        volume = distinct >= cfg.min_distinct_apis and services >= cfg.min_services
        denial_storm = denials >= cfg.min_denied
        if not (volume or denial_storm):
            return []
        if (
            not denial_storm
            and self.config.baseline.suppress_familiar
            and distinct <= historical_peak * cfg.peak_margin
        ):
            return []
        if denial_storm and volume:
            severity = Severity.HIGH
        elif denial_storm:
            severity = Severity.MEDIUM if ctx.warmed_up else Severity.LOW
        else:
            severity = Severity.HIGH if ctx.warmed_up else Severity.MEDIUM
        in_window = ctx.now - burst.last_fired < cfg.window_minutes * 60
        if in_window and severity <= burst.last_severity:
            return []
        burst.last_fired, burst.last_severity = ctx.now, severity
        return [
            self.finding(
                ctx,
                severity,
                "Enumeration burst",
                f"{distinct} distinct discovery APIs across {services} services and {denials} "
                f"access denials within {cfg.window_minutes:.0f} min "
                f"(historical daily peak {historical_peak:.0f})",
                evidence=tuple(burst.recent_ids),
                dedup_key=f"{int(ctx.now // (cfg.window_minutes * 60))}",
                attrs={"distinct_apis": distinct, "services": services, "denied": denials},
            )
        ]
