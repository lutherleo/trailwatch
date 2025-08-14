"""Rule interface and the per-event context every rule receives.

Rules are plain Python classes ("rules as code"): each declares an id, a description and the
MITRE ATT&CK techniques it covers, owns its own bounded state, and turns one
:class:`EventContext` into zero or more :class:`~trailwatch.model.Finding` objects. Rules run
*before* the baseline is updated with the current event, so "new" really means new.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from trailwatch.baseline import BaselineStore, PrincipalProfile
from trailwatch.config import Config
from trailwatch.model import Event, Finding, Severity
from trailwatch.netmap import NetInfo


@dataclass(slots=True)
class EventContext:
    """One event plus everything derived from it that rules need."""

    event: Event
    net: NetInfo | None
    ua_family: str
    profile: PrincipalProfile | None
    baseline: BaselineStore
    config: Config
    warmed_up: bool
    habits: list[str] = field(default_factory=list)

    @property
    def now(self) -> float:
        return self.event.time

    @property
    def principal(self) -> str:
        return self.event.principal

    @property
    def asn(self) -> str | None:
        return self.net.asn_label if self.net else None

    @property
    def location(self) -> str:
        return f"{self.net.city}, {self.net.country}" if self.net else "unknown location"

    def familiar(self, weight: float) -> bool:
        return weight >= self.config.baseline.familiar_min_weight


class Rule(abc.ABC):
    """Base class for detection rules."""

    rule_id: ClassVar[str]
    description: ClassVar[str]
    techniques: ClassVar[tuple[str, ...]] = ()

    def __init__(self, config: Config) -> None:
        self.config = config

    @abc.abstractmethod
    def evaluate(self, ctx: EventContext) -> list[Finding]:
        """Return findings for this event (empty list when nothing is suspicious)."""

    def state_size(self) -> int:
        """Number of principals this rule currently holds state for (for bound checks)."""
        return 0

    def finding(
        self,
        ctx: EventContext,
        severity: Severity,
        title: str,
        detail: str,
        evidence: Iterable[str] | None = None,
        dedup_key: str = "",
        attrs: Mapping[str, Any] | None = None,
        techniques: tuple[str, ...] | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=severity,
            principal=ctx.principal,
            time=ctx.now,
            title=title,
            detail=detail,
            evidence=tuple(evidence) if evidence is not None else (ctx.event.event_id,),
            dedup_key=dedup_key,
            techniques=techniques if techniques is not None else self.techniques,
            attrs=dict(attrs or {}),
        )
