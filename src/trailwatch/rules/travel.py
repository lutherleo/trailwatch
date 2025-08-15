"""Impossible travel: consecutive geolocated calls further apart than a plane could fly."""

from __future__ import annotations

from dataclasses import dataclass

from trailwatch.baseline import Dim
from trailwatch.config import Config
from trailwatch.model import Finding
from trailwatch.netmap import haversine_km
from trailwatch.rules.base import EventContext, Rule
from trailwatch.window import BoundedLRU

# Coarse or relayed geolocation: a jump involving these is weaker evidence.
IMPRECISE_KINDS = frozenset({"vpn", "mobile"})


@dataclass(frozen=True, slots=True)
class _Fix:
    time: float
    lat: float
    lon: float
    asn: str
    kind: str
    place: str
    event_id: str


class ImpossibleTravelRule(Rule):
    rule_id = "impossible_travel"
    description = (
        "Two calls by the same principal from locations whose great-circle distance implies a "
        "speed above travel.max_speed_kmh. Suppressed when both networks are familiar to the "
        "principal (corporate VPN egress, split tunnels); downgraded for VPN/mobile networks."
    )
    techniques = ("T1078.004",)

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._last: BoundedLRU[str, _Fix] = BoundedLRU(config.state.max_rule_principals)

    def state_size(self) -> int:
        return len(self._last)

    def evaluate(self, ctx: EventContext) -> list[Finding]:
        cfg = self.config.travel
        net = ctx.net
        if not cfg.enabled or net is None:
            return []
        current = _Fix(
            ctx.now, net.lat, net.lon, net.asn_label, net.kind, ctx.location, ctx.event.event_id
        )
        previous = self._last.get(ctx.principal)
        if previous is not None and previous.time > ctx.now:
            return []  # late event: never rewind the principal's last known position
        self._last.put(ctx.principal, current)
        if previous is None or previous.asn == current.asn:
            return []
        distance = haversine_km(previous.lat, previous.lon, current.lat, current.lon)
        if distance < cfg.min_distance_km:
            return []
        hours = max(ctx.now - previous.time, 1.0) / 3600.0
        speed = distance / hours
        if speed <= cfg.max_speed_kmh:
            return []
        profile = ctx.profile
        if (
            self.config.baseline.suppress_familiar
            and profile is not None
            and ctx.familiar(profile.weight(Dim.ASN, previous.asn, ctx.now))
            and ctx.familiar(profile.weight(Dim.ASN, current.asn, ctx.now))
        ):
            return []
        severity = cfg.severity
        if previous.kind in IMPRECISE_KINDS or current.kind in IMPRECISE_KINDS:
            severity = severity.bump(-1)
        if not ctx.warmed_up:
            severity = severity.bump(-1)
        minutes = (ctx.now - previous.time) / 60.0
        pair = "|".join(sorted((previous.asn, current.asn)))
        return [
            self.finding(
                ctx,
                severity,
                f"Impossible travel: {previous.place} -> {current.place}",
                f"{distance:.0f} km in {minutes:.1f} min ({speed:.0f} km/h) between "
                f"{previous.asn} and {current.asn}",
                evidence=(previous.event_id, current.event_id),
                dedup_key=pair,
                attrs={"distance_km": round(distance, 1), "speed_kmh": round(speed, 1)},
            )
        ]
