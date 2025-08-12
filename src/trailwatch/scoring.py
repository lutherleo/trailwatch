"""Per-principal risk scoring with exponential decay.

``score(t) = sum_i w(severity_i) * 2^(-(t - t_i) / half_life)``, maintained incrementally in O(1)
per finding: the stored score is decayed to the new finding's time and the new weight is added.
A principal "crosses" when its score rises from below ``threshold`` to at or above it; the
scorer keeps the most recent contributing findings (bounded) so a risk alert can explain itself.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from trailwatch.config import ScoringConfig
from trailwatch.model import Finding
from trailwatch.window import BoundedLRU, decay_factor


@dataclass(slots=True)
class RiskState:
    score: float
    updated: float
    contributions: deque[Finding] = field(default_factory=deque)

    def decayed(self, now: float, half_life: float) -> float:
        return self.score * decay_factor(now - self.updated, half_life)


@dataclass(frozen=True, slots=True)
class Crossing:
    """A principal's risk score crossed the alert threshold."""

    principal: str
    time: float
    score: float
    contributions: tuple[Finding, ...]


class RiskScorer:
    def __init__(self, cfg: ScoringConfig, max_principals: int) -> None:
        self.cfg = cfg
        self.half_life = cfg.half_life_hours * 3600.0
        self._states: BoundedLRU[str, RiskState] = BoundedLRU(max_principals)

    def __len__(self) -> int:
        return len(self._states)

    def score(self, principal: str, now: float) -> float:
        state = self._states.peek(principal)
        return state.decayed(now, self.half_life) if state else 0.0

    def add(self, finding: Finding) -> Crossing | None:
        """Add one finding's weight; return a :class:`Crossing` if the threshold was crossed."""
        weight = self.cfg.weight(finding.severity)
        if weight <= 0:
            return None
        state = self._states.get(finding.principal)
        if state is None:
            state = RiskState(score=0.0, updated=finding.time)
            self._states.put(finding.principal, state)
        when = max(finding.time, state.updated)
        before = state.decayed(when, self.half_life)
        state.score = before + weight
        state.updated = when
        # Contributions older than ~4 half-lives carry < 7% of their weight; drop them.
        horizon = when - 4 * self.half_life
        while state.contributions and state.contributions[0].time < horizon:
            state.contributions.popleft()
        state.contributions.append(finding)
        while len(state.contributions) > self.cfg.max_contributions:
            state.contributions.popleft()
        if before < self.cfg.threshold <= state.score:
            return Crossing(
                principal=finding.principal,
                time=when,
                score=state.score,
                contributions=tuple(state.contributions),
            )
        return None
