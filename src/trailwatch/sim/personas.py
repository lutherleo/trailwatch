"""Benign principals: humans with schedules, habits and travel, and automation roles.

Each persona produces one simulated day of CloudTrail records at a time. The benign population
deliberately contains the behaviours that make real CloudTrail detection noisy -- business
travel, split-tunnel VPN egress on another continent, mobile networks geolocated far away, SSO
console sign-ins that report ``MFAUsed: No``, legacy users without MFA, routine access-key
creation by admins, scheduled posture scanners that enumerate everything, Terraform runs that
touch dozens of APIs, new tools and new regions -- so that evaluation measures false positives
against something harder than a quiet baseline.
"""

from __future__ import annotations

import abc
import random
import zlib
from dataclasses import dataclass, field
from typing import Any

from trailwatch.sim import catalog as cat
from trailwatch.sim.catalog import Api
from trailwatch.sim.records import Emitter, Principal

DAY = 86_400.0
HOUR = 3_600.0
Record = dict[str, Any]


@dataclass(slots=True)
class DayContext:
    index: int
    start: float
    rng: random.Random
    emit: Emitter

    @property
    def weekday(self) -> int:
        return int((self.start // DAY + 3) % 7)  # 1970-01-01 was a Thursday; 0 = Monday

    @property
    def is_weekend(self) -> bool:
        return self.weekday >= 5

    @property
    def ua_version(self) -> int:
        return 20 + self.index // 30  # SDK versions drift monthly


def weighted(
    rng: random.Random, items: tuple[tuple[Any, float], ...] | list[tuple[Any, float]]
) -> Any:
    population = [item for item, _ in items]
    weights = [weight for _, weight in items]
    return rng.choices(population, weights)[0]


def poisson_gaps(rng: random.Random, n: int, mean_gap: float) -> list[float]:
    out, t = [], 0.0
    for _ in range(n):
        out.append(t)
        t += rng.expovariate(1.0 / mean_gap)
    return out


class Persona(abc.ABC):
    """A simulated principal. ``tags`` drive incident victim selection."""

    def __init__(self, principal: Principal, tags: frozenset[str]) -> None:
        self.principal = principal
        self.tags = tags

    @abc.abstractmethod
    def day(self, ctx: DayContext) -> list[Record]:
        """All benign records this principal produces on day ``ctx.index``."""

    def active_window(self, ctx: DayContext) -> tuple[float, float]:
        """UTC interval when this principal is typically active (incidents aim inside it)."""
        return ctx.start, ctx.start + DAY


@dataclass(slots=True)
class Trip:
    first_day: int
    last_day: int
    asn: int
    utc_offset: float


@dataclass(slots=True)
class HumanProfile:
    home: tuple[tuple[int, float], ...]
    utc_offset: float
    apis: tuple[tuple[Api, float], ...]
    regions: tuple[tuple[str, float], ...]
    cli_family: str = "aws-cli"
    console_share: float = 0.3
    mfa: bool = True
    sessions: tuple[int, int] = (1, 3)
    calls: tuple[int, int] = (8, 35)
    weekend_prob: float = 0.08
    explore_prob: float = 0.04
    new_region_prob: float = 0.01
    console_only: bool = False
    trips: list[Trip] = field(default_factory=list)
    extra_family: str | None = None
    extra_family_from: int = 10_000


class Human(Persona):
    """An employee: weekday sessions from office/home/mobile networks, CLI and console."""

    def __init__(self, principal: Principal, tags: frozenset[str], profile: HumanProfile) -> None:
        super().__init__(principal, tags)
        self.p = profile
        self._extra_regions: list[str] = []
        self._slot = zlib.crc32(principal.name.encode()) % 4093

    def _trip(self, day: int) -> Trip | None:
        for trip in self.p.trips:
            if trip.first_day <= day <= trip.last_day:
                return trip
        return None

    def _offset(self, day: int) -> float:
        trip = self._trip(day)
        return trip.utc_offset if trip else self.p.utc_offset

    def active_window(self, ctx: DayContext) -> tuple[float, float]:
        local_midnight = ctx.start - self._offset(ctx.index) * HOUR
        return local_midnight + 10 * HOUR, local_midnight + 16 * HOUR

    def _network(self, ctx: DayContext, slot: int) -> tuple[int, str]:
        trip = self._trip(ctx.index)
        if trip is not None:
            return trip.asn, ctx.emit.stable_ip(trip.asn, self._slot + slot)
        asn: int = weighted(ctx.rng, self.p.home)
        return asn, ctx.emit.stable_ip(asn, self._slot + asn + ctx.rng.randrange(3))

    def _region(self, ctx: DayContext) -> str:
        if self._extra_regions and ctx.rng.random() < 0.1:
            return ctx.rng.choice(self._extra_regions)
        region: str = weighted(ctx.rng, self.p.regions)
        return region

    def _travelling(self, day: int) -> bool:
        """The day before a trip starts and the day after it ends are spent in the air."""
        return any(day in (t.first_day - 1, t.last_day + 1) for t in self.p.trips)

    def day(self, ctx: DayContext) -> list[Record]:
        rng = ctx.rng
        if self._travelling(ctx.index):
            return []
        if ctx.is_weekend and rng.random() >= self.p.weekend_prob:
            return []
        if rng.random() < self.p.new_region_prob:
            self._extra_regions.append(rng.choice(cat.REGIONS))
        local_midnight = ctx.start - self._offset(ctx.index) * HOUR
        n_sessions = rng.randint(*self.p.sessions)
        start = local_midnight + min(20.0, max(6.5, rng.gauss(9.5, 1.2))) * HOUR
        records: list[Record] = []
        for slot in range(n_sessions):
            records.extend(self._session(ctx, start, slot))
            start += rng.uniform(1.5, 3.5) * HOUR
        return records

    def _session(self, ctx: DayContext, start: float, slot: int) -> list[Record]:
        rng, emit, who = ctx.rng, ctx.emit, self.principal
        _, ip = self._network(ctx, slot)
        console = self.p.console_only or rng.random() < self.p.console_share
        records: list[Record] = []
        if console:
            browser = cat.user_agent("browser", 4 + ctx.index // 45)
            records.append(emit.console_login(who, start, ip, browser, self.p.mfa))
            family = "console"
        elif self.p.extra_family and ctx.index >= self.p.extra_family_from and rng.random() < 0.4:
            family = self.p.extra_family
        else:
            family = self.p.cli_family
        ua = cat.user_agent(family, ctx.ua_version)
        n_calls = rng.randint(*self.p.calls)
        for offset in poisson_gaps(rng, n_calls, 45.0):
            api: Api = weighted(rng, self.p.apis)
            if rng.random() < self.p.explore_prob / max(1, n_calls / 10):
                api = rng.choice(cat.EXPLORATION_APIS)
            records.append(
                emit.record(
                    who,
                    start + 20 + offset,
                    api,
                    self._region(ctx),
                    ip,
                    ua,
                    mfa=self.p.mfa,
                    console=console,
                )
            )
        return records


class Admin(Human):
    """A cloud administrator: IAM reads/writes and routine onboarding with MFA."""

    def __init__(self, principal: Principal, tags: frozenset[str], profile: HumanProfile) -> None:
        super().__init__(principal, tags, profile)
        self._hires = 0

    def day(self, ctx: DayContext) -> list[Record]:
        records = super().day(ctx)
        if records and not ctx.is_weekend and ctx.rng.random() < 0.18:
            records.extend(self._onboard(ctx))
        return records

    def _onboard(self, ctx: DayContext) -> list[Record]:
        rng, emit, who = ctx.rng, ctx.emit, self.principal
        self._hires += 1
        new_user = f"{who.name.split('-')[0]}-hire-{self._hires:03d}"
        _, ip = self._network(ctx, 9)
        ua = cat.user_agent("console", 0)
        t = self.active_window(ctx)[0] + rng.uniform(0, 4 * HOUR)
        steps: list[tuple[Api, dict[str, Any]]] = [
            (("iam", "CreateUser", False), {"userName": new_user}),
            (("iam", "AddUserToGroup", False), {"userName": new_user, "groupName": "developers"}),
            (("iam", "CreateLoginProfile", False), {"userName": new_user}),
            (("iam", "CreateAccessKey", False), {"userName": new_user}),
        ]
        out = []
        for i, (api, params) in enumerate(steps):
            out.append(
                emit.record(
                    who,
                    t + 40 * i,
                    api,
                    "us-east-1",
                    ip,
                    ua,
                    mfa=True,
                    console=True,
                    params=params,
                )
            )
        return out


class LegacyAdmin(Human):
    """A long-tenured user without MFA who occasionally makes IAM changes from the console."""

    def day(self, ctx: DayContext) -> list[Record]:
        records = super().day(ctx)
        if not records or ctx.rng.random() >= 0.03:
            return records
        base = self.active_window(ctx)[0] + ctx.rng.uniform(0, HOUR)
        ip = records[0]["sourceIPAddress"]
        api: Api = ctx.rng.choice(
            [("iam", "UpdateLoginProfile", False), ("iam", "AttachUserPolicy", False)]
        )
        login = ctx.emit.console_login(
            self.principal, base, ip, cat.user_agent("browser", 4), mfa=False
        )
        change = ctx.emit.record(
            self.principal,
            base + 300,
            api,
            "us-east-1",
            ip,
            cat.user_agent("console", 0),
            mfa=False,
            console=True,
            params={"userName": f"contractor-{ctx.rng.randrange(1, 9)}"},
        )
        return [*records, login, change]


class Automation(Persona):
    """A role used by machines: fixed network, fixed tool, schedule-driven."""

    def __init__(
        self,
        principal: Principal,
        tags: frozenset[str],
        asn: int | None,
        family: str,
    ) -> None:
        super().__init__(principal, tags)
        self.asn = asn
        self.family = family

    def ip(self, ctx: DayContext) -> str:
        if self.asn is None:
            return f"{cat.UNMAPPED_PREFIX}{ctx.rng.randrange(10, 250)}"
        return ctx.emit.ip_in(self.asn)

    def ua(self, ctx: DayContext) -> str:
        return cat.user_agent(self.family, ctx.ua_version)


class CiRole(Automation):
    """Terraform pipeline: several plan/apply runs on weekdays touching ~25 read APIs each."""

    def __init__(self, principal: Principal, tags: frozenset[str], teardown_day: int | None):
        super().__init__(principal, tags, cat.ASN_CI, "terraform")
        self.teardown_day = teardown_day

    def active_window(self, ctx: DayContext) -> tuple[float, float]:
        return ctx.start + 15 * HOUR, ctx.start + 24 * HOUR

    def day(self, ctx: DayContext) -> list[Record]:
        rng = ctx.rng
        runs = rng.randint(0, 1) if ctx.is_weekend else rng.randint(2, 6)
        records: list[Record] = []
        for _ in range(runs):
            t = ctx.start + rng.uniform(14, 26) * HOUR  # US working hours in UTC
            ip, ua = self.ip(ctx), self.ua(ctx)
            region = weighted(rng, (("us-east-1", 0.7), ("us-west-2", 0.3)))
            reads = [a for a in cat.TERRAFORM_READS if rng.random() < 0.85]
            for api in reads:
                t += rng.uniform(0.2, 2.0)
                records.append(ctx.emit.record(self.principal, t, api, region, ip, ua))
            for api in rng.sample(cat.TERRAFORM_WRITES, rng.randint(0, 3)):
                t += rng.uniform(1, 5)
                params: dict[str, Any] | None = None
                if api[1] == "UpdateTrail":
                    params = {"name": "org-trail", "enableLogFileValidation": True}
                records.append(
                    ctx.emit.record(self.principal, t, api, region, ip, ua, params=params)
                )
        if self.teardown_day == ctx.index:
            # Benign but alarming: tearing down a sandbox environment deletes its trail.
            t = ctx.start + 20 * HOUR
            name = f"sandbox-trail-{rng.randrange(100, 999)}"
            records.append(
                ctx.emit.record(
                    self.principal,
                    t,
                    ("cloudtrail", "DeleteTrail", False),
                    "us-west-2",
                    self.ip(ctx),
                    self.ua(ctx),
                    params={"name": name},
                )
            )
        return records


class ScannerRole(Automation):
    """Third-party posture scanner: enumerates every service in several regions every 8 h."""

    def __init__(self, principal: Principal, tags: frozenset[str]) -> None:
        super().__init__(principal, tags, cat.ASN_VENDOR, "aws-sdk-java")

    def day(self, ctx: DayContext) -> list[Record]:
        records: list[Record] = []
        rng = ctx.rng
        for hour in (1, 9, 17):
            t = ctx.start + hour * HOUR + rng.uniform(0, 600)
            ip, ua = self.ip(ctx), self.ua(ctx)
            for region in ("us-east-1", "us-west-2"):
                for api in cat.SCANNER_APIS:
                    if rng.random() < 0.9:
                        t += rng.uniform(0.1, 1.5)
                        records.append(ctx.emit.record(self.principal, t, api, region, ip, ua))
        return records


class PipelineRole(Automation):
    """Hourly data-pipeline jobs from the on-prem data centre, 24/7."""

    def __init__(self, principal: Principal, tags: frozenset[str]) -> None:
        super().__init__(principal, tags, cat.ASN_DATACENTER, "boto3")

    def day(self, ctx: DayContext) -> list[Record]:
        records: list[Record] = []
        rng = ctx.rng
        for hour in range(24):
            t = ctx.start + hour * HOUR + rng.uniform(0, 300)
            ip, ua = self.ip(ctx), self.ua(ctx)
            for _ in range(rng.randint(3, 6)):
                t += rng.uniform(1, 30)
                api: Api = weighted(rng, cat.PIPELINE_APIS)
                records.append(ctx.emit.record(self.principal, t, api, "us-west-2", ip, ua))
        return records


class AppRole(Automation):
    """An application's instance role calling from cloud egress addresses (not in the netmap)."""

    def __init__(self, principal: Principal, tags: frozenset[str]) -> None:
        super().__init__(principal, tags, None, "aws-sdk-go")

    def day(self, ctx: DayContext) -> list[Record]:
        records: list[Record] = []
        rng = ctx.rng
        t = ctx.start + rng.uniform(0, 1800)
        while t < ctx.start + DAY:
            ip, ua = self.ip(ctx), self.ua(ctx)
            for _ in range(rng.randint(1, 3)):
                api: Api = weighted(rng, cat.APP_ROLE_APIS)
                records.append(ctx.emit.record(self.principal, t, api, "us-east-1", ip, ua))
                t += rng.uniform(0.5, 5)
            t += rng.uniform(1200, 2400)
        return records


class ServiceActivity(Persona):
    """AWS services acting on the account's behalf (``userIdentity.type = AWSService``)."""

    def day(self, ctx: DayContext) -> list[Record]:
        records = []
        for _ in range(ctx.rng.randint(2, 6)):
            t = ctx.start + ctx.rng.uniform(0, DAY)
            record = ctx.emit.record(
                self.principal,
                t,
                ("sts", "AssumeRole", True),
                "us-east-1",
                "config.amazonaws.com",
                "config.amazonaws.com",
            )
            record["userIdentity"] = {"type": "AWSService", "invokedBy": "config.amazonaws.com"}
            records.append(record)
        return records


def plan_trips(rng: random.Random, days: int, home_offset: float) -> list[Trip]:
    """Business trips of 3-6 days every 4-7 weeks, bracketed by a day in the air each way."""
    trips: list[Trip] = []
    day = rng.randint(10, 25)
    while day < days - 5:
        length = rng.randint(3, 6)
        asn = rng.choice(cat.TRAVEL_ASNS)
        offsets = {
            cat.ASN_LONDON_HOTEL: 0.0,
            cat.ASN_TOKYO_ISP: 9.0,
            cat.ASN_SINGAPORE_ISP: 8.0,
            cat.ASN_TORONTO_ISP: -5.0,
            cat.ASN_MUNICH_ISP: 1.0,
            cat.ASN_SYDNEY_ISP: 10.0,
        }
        trips.append(Trip(day + 2, day + 1 + length, asn, offsets.get(asn, home_offset)))
        day += length + rng.randint(25, 45)
    return trips
