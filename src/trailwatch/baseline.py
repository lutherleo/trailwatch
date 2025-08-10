"""Per-principal behavioural baselines.

A :class:`PrincipalProfile` remembers, with exponential decay, which APIs, regions, user-agent
families, networks (ASNs) and countries a principal uses. "Familiar" means a decayed weight at or
above ``familiar_min_weight``; "new" means a weight of zero (never seen, or forgotten long ago,
or pruned from the bounded top-K). Account-wide statistics give a population view used to judge
whether an API that is new for one principal is also globally rare.

All containers are bounded (see :mod:`trailwatch.window`), and the profile table itself is an
LRU over principals, so memory is O(max_principals x per-profile caps).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

from trailwatch.config import BaselineConfig
from trailwatch.window import BoundedLRU, DecayedCounter

DAY = 86_400.0


class Dim(enum.StrEnum):
    """Baselined dimensions."""

    API = "api"
    REGION = "region"
    UA = "ua"
    ASN = "asn"
    COUNTRY = "country"
    HABIT = "habit"


@dataclass(frozen=True, slots=True)
class Observation:
    """The baseline-relevant facts extracted from one enriched event."""

    time: float
    api: str
    region: str
    ua_family: str
    asn: str | None
    country: str | None
    habits: tuple[str, ...] = ()


def _caps(cfg: BaselineConfig) -> dict[Dim, int]:
    return {
        Dim.API: cfg.max_apis,
        Dim.REGION: cfg.max_regions,
        Dim.UA: cfg.max_ua_families,
        Dim.ASN: cfg.max_asns,
        Dim.COUNTRY: cfg.max_countries,
        Dim.HABIT: 64,
    }


@dataclass(slots=True)
class PrincipalProfile:
    """Decayed behavioural history of one principal."""

    first_seen: float
    last_seen: float
    events: int
    counters: dict[Dim, DecayedCounter]
    recon_peak: float = 0.0
    recon_day: int = -1
    recon_day_max: int = 0

    @classmethod
    def new(cls, now: float, cfg: BaselineConfig) -> PrincipalProfile:
        half_life = cfg.half_life_days * DAY
        counters = {dim: DecayedCounter(half_life, cap) for dim, cap in _caps(cfg).items()}
        return cls(first_seen=now, last_seen=now, events=0, counters=counters)

    def warmed_up(self, now: float, cfg: BaselineConfig) -> bool:
        return self.events >= cfg.warmup_events and (now - self.first_seen) >= cfg.warmup_days * DAY

    def weight(self, dim: Dim, value: str, now: float) -> float:
        return self.counters[dim].weight(value, now)

    def is_new(self, dim: Dim, value: str) -> bool:
        return value not in self.counters[dim]

    def is_familiar(self, dim: Dim, value: str, now: float, cfg: BaselineConfig) -> bool:
        return self.weight(dim, value, now) >= cfg.familiar_min_weight

    def observe(self, obs: Observation) -> None:
        self.events += 1
        self.first_seen = min(self.first_seen, obs.time)
        self.last_seen = max(self.last_seen, obs.time)
        self.counters[Dim.API].add(obs.api, obs.time)
        self.counters[Dim.REGION].add(obs.region, obs.time)
        self.counters[Dim.UA].add(obs.ua_family, obs.time)
        if obs.asn is not None:
            self.counters[Dim.ASN].add(obs.asn, obs.time)
        if obs.country is not None:
            self.counters[Dim.COUNTRY].add(obs.country, obs.time)
        for habit in obs.habits:
            self.counters[Dim.HABIT].add(habit, obs.time)

    def record_recon(self, now: float, distinct: int) -> None:
        """Track the per-day peak of distinct reconnaissance APIs inside one burst window.

        ``recon_peak`` only ever holds peaks from *previous* days, so a burst is always compared
        against history, never against itself.
        """
        day = int(now // DAY)
        if day != self.recon_day:
            if self.recon_day >= 0:
                self.recon_peak = max(self.recon_peak * 0.98, float(self.recon_day_max))
            self.recon_day = day
            self.recon_day_max = 0
        self.recon_day_max = max(self.recon_day_max, distinct)

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "events": self.events,
            "recon": [self.recon_peak, self.recon_day, self.recon_day_max],
            "counters": {dim.value: c.to_dict() for dim, c in self.counters.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], cfg: BaselineConfig) -> PrincipalProfile:
        profile = cls.new(float(data["first_seen"]), cfg)
        profile.last_seen = float(data["last_seen"])
        profile.events = int(data["events"])
        peak, day, day_max = data.get("recon", [0.0, -1, 0])
        profile.recon_peak, profile.recon_day, profile.recon_day_max = (
            float(peak),
            int(day),
            int(day_max),
        )
        for dim_name, counter in data.get("counters", {}).items():
            profile.counters[Dim(dim_name)] = DecayedCounter.from_dict(counter)
        return profile


@dataclass(slots=True)
class GlobalStats:
    """Account-wide (population) API and region statistics."""

    apis: DecayedCounter
    regions: DecayedCounter

    def api_share(self, api: str, now: float) -> float:
        total = self.apis.total(now)
        return self.apis.weight(api, now) / total if total > 0 else 0.0


class BaselineStore:
    """LRU table of principal profiles plus population statistics."""

    def __init__(self, cfg: BaselineConfig) -> None:
        self.cfg = cfg
        self._profiles: BoundedLRU[str, PrincipalProfile] = BoundedLRU(cfg.max_principals)
        half_life = cfg.half_life_days * DAY
        self.global_stats = GlobalStats(
            apis=DecayedCounter(half_life, cfg.max_apis * 8),
            regions=DecayedCounter(half_life, 64),
        )

    def __len__(self) -> int:
        return len(self._profiles)

    @property
    def evictions(self) -> int:
        return self._profiles.evictions

    def get(self, principal: str) -> PrincipalProfile | None:
        return self._profiles.get(principal)

    def profile(self, principal: str, now: float) -> PrincipalProfile:
        return self._profiles.get_or_create(principal, lambda: PrincipalProfile.new(now, self.cfg))

    def observe(self, principal: str, obs: Observation) -> PrincipalProfile:
        profile = self.profile(principal, obs.time)
        profile.observe(obs)
        self.global_stats.apis.add(obs.api, obs.time)
        self.global_stats.regions.add(obs.region, obs.time)
        return profile

    def principals(self) -> list[str]:
        return self._profiles.keys()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "profiles": {key: p.to_dict() for key, p in self._profiles.items()},
            "global": {
                "apis": self.global_stats.apis.to_dict(),
                "regions": self.global_stats.regions.to_dict(),
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], cfg: BaselineConfig) -> BaselineStore:
        if data.get("version") != 1:
            raise ValueError(f"unsupported baseline snapshot version {data.get('version')!r}")
        store = cls(cfg)
        for key, raw in data.get("profiles", {}).items():
            store._profiles.put(str(key), PrincipalProfile.from_dict(raw, cfg))
        glob = data.get("global", {})
        if "apis" in glob:
            store.global_stats.apis = DecayedCounter.from_dict(glob["apis"])
        if "regions" in glob:
            store.global_stats.regions = DecayedCounter.from_dict(glob["regions"])
        return store
