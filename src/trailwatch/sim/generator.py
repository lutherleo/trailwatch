"""The simulator: a seeded population, an incident plan, and a time-ordered labeled stream.

Determinism: every persona-day and every incident draws from its own RNG seeded by
``(seed, persona index, day)`` / ``(seed, incident id)``, so the benign traffic of a seed is
byte-identical whether or not incidents are injected, and runs are reproducible across
machines and processes (string seeds, no ``hash()``).
"""

from __future__ import annotations

import gzip
import heapq
import json
import random
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from trailwatch.netmap import NetMap
from trailwatch.sim import catalog as cat
from trailwatch.sim.incidents import SCENARIOS
from trailwatch.sim.personas import (
    DAY,
    Admin,
    AppRole,
    CiRole,
    DayContext,
    Human,
    HumanProfile,
    LegacyAdmin,
    Persona,
    PipelineRole,
    ScannerRole,
    ServiceActivity,
    plan_trips,
)
from trailwatch.sim.records import ACCOUNT_ID, Emitter, make_principal

Record = dict[str, Any]
Labeled = tuple[Record, str | None]

US = (("us-east-1", 0.6), ("us-west-2", 0.4))
EU = (("eu-west-1", 0.7), ("eu-central-1", 0.3))
IN = (("ap-south-1", 0.7), ("us-east-1", 0.3))


class SimulationError(ValueError):
    """Invalid simulation parameters."""


@dataclass(frozen=True)
class SimConfig:
    seed: int = 1
    days: int = 90
    start: str = "2026-01-05"  # a Monday
    incidents_per_scenario: int = 2
    incident_start_day: int | None = None  # default: day 21, or a third in for short runs
    scenarios: tuple[str, ...] = tuple(SCENARIOS)

    def __post_init__(self) -> None:
        if self.days < 2:
            raise SimulationError("days must be >= 2")
        if self.incidents_per_scenario < 0:
            raise SimulationError("incidents_per_scenario must be >= 0")
        if self.incidents_per_scenario and not 0 <= self.first_incident_day <= self.days - 2:
            raise SimulationError("incident_start_day must fall inside the simulated period")
        unknown = sorted(set(self.scenarios) - set(SCENARIOS))
        if unknown:
            raise SimulationError(f"unknown scenario(s): {', '.join(unknown)}")

    @property
    def first_incident_day(self) -> int:
        if self.incident_start_day is not None:
            return self.incident_start_day
        return min(21, self.days // 3)

    @property
    def start_epoch(self) -> float:
        try:
            return datetime.fromisoformat(self.start).replace(tzinfo=UTC).timestamp()
        except ValueError as exc:
            raise SimulationError(f"invalid start date {self.start!r}") from exc


@dataclass(slots=True)
class Incident:
    incident_id: str
    scenario: str
    victim: str
    principal: str
    day: int
    description: str
    start: float = 0.0
    end: float = 0.0
    events: int = 0
    event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("event_ids")
        return data


def build_population(rng: random.Random, days: int) -> list[Persona]:
    """The benign principals of one simulated account (19 identities)."""

    def human(name: str, kind: str = "user") -> Any:
        return make_principal(rng, kind, name, session=name if kind == "sso" else "")

    dev = frozenset({"human", "cli_user"})
    people: list[Persona] = [
        Human(
            human("dev-01"),
            dev,
            HumanProfile(
                home=((cat.ASN_HQ, 0.65), (cat.ASN_SEATTLE_ISP, 0.3), (cat.ASN_US_MOBILE, 0.05)),
                utc_offset=-8,
                apis=cat.DEV_APIS,
                regions=US,
                trips=plan_trips(rng, days, -8),
            ),
        ),
        Human(
            human("dev-02"),
            dev,
            HumanProfile(
                home=(
                    (cat.ASN_HQ, 0.5),
                    (cat.ASN_SEATTLE_ISP, 0.25),
                    (cat.ASN_VPN_FRANKFURT, 0.25),
                ),
                utc_offset=-8,
                apis=cat.DEV_APIS,
                regions=US,
            ),
        ),
        Human(
            human("dev-03"),
            dev,
            HumanProfile(
                home=((cat.ASN_AUSTIN_ISP, 0.9), (cat.ASN_CHICAGO_MOBILE, 0.1)),
                utc_offset=-6,
                apis=cat.DEV_APIS,
                regions=US,
                cli_family="boto3",
                extra_family="terraform",
                extra_family_from=rng.randint(days // 3, days),
            ),
        ),
        Human(
            human("dev-04"),
            dev,
            HumanProfile(
                home=(
                    (cat.ASN_DUBLIN_OFFICE, 0.6),
                    (cat.ASN_DUBLIN_ISP, 0.3),
                    (cat.ASN_IE_MOBILE, 0.1),
                ),
                utc_offset=0,
                apis=cat.DEV_APIS,
                regions=EU,
                trips=plan_trips(rng, days, 0),
            ),
        ),
        Human(
            human("dev-05"),
            dev,
            HumanProfile(
                home=(
                    (cat.ASN_DUBLIN_OFFICE, 0.5),
                    (cat.ASN_DUBLIN_ISP, 0.25),
                    (cat.ASN_VPN_ASHBURN, 0.25),
                ),
                utc_offset=0,
                apis=cat.DEV_APIS,
                regions=EU,
            ),
        ),
        Human(
            human("dev-06"),
            dev,
            HumanProfile(
                home=((cat.ASN_BENGALURU_ISP, 1.0),),
                utc_offset=5.5,
                apis=cat.DEV_APIS,
                regions=IN,
                extra_family="boto3",
                extra_family_from=rng.randint(days // 3, days),
            ),
        ),
        Human(
            human("dev-07", "sso"),
            frozenset({"human"}),
            HumanProfile(
                home=((cat.ASN_HQ, 0.7), (cat.ASN_SEATTLE_ISP, 0.3)),
                utc_offset=-8,
                apis=cat.DEV_APIS,
                regions=US,
                console_share=0.5,
            ),
        ),
        Human(
            human("dev-08", "sso"),
            frozenset({"human"}),
            HumanProfile(
                home=((cat.ASN_HQ, 0.6), (cat.ASN_SEATTLE_ISP, 0.4)),
                utc_offset=-8,
                apis=cat.DEV_APIS,
                regions=US,
                console_share=0.5,
            ),
        ),
        Admin(
            human("admin-01"),
            frozenset({"human", "admin"}),
            HumanProfile(
                home=((cat.ASN_HQ, 0.8), (cat.ASN_SEATTLE_ISP, 0.2)),
                utc_offset=-8,
                apis=cat.ADMIN_APIS,
                regions=US,
                console_share=0.5,
            ),
        ),
        Admin(
            human("admin-02"),
            frozenset({"human", "admin"}),
            HumanProfile(
                home=((cat.ASN_DUBLIN_OFFICE, 0.8), (cat.ASN_DUBLIN_ISP, 0.2)),
                utc_offset=0,
                apis=cat.ADMIN_APIS,
                regions=EU,
                console_share=0.5,
            ),
        ),
        LegacyAdmin(
            human("legacy-01"),
            frozenset({"human", "no_mfa"}),
            HumanProfile(
                home=((cat.ASN_AUSTIN_ISP, 1.0),),
                utc_offset=-6,
                apis=cat.LEGACY_APIS,
                regions=US,
                mfa=False,
                console_only=True,
                sessions=(1, 2),
                calls=(5, 20),
            ),
        ),
        Human(
            human("legacy-02"),
            frozenset({"human", "no_mfa"}),
            HumanProfile(
                home=((cat.ASN_DUBLIN_ISP, 1.0),),
                utc_offset=0,
                apis=cat.LEGACY_APIS,
                regions=EU,
                mfa=False,
                console_only=True,
                sessions=(1, 2),
                calls=(5, 20),
            ),
        ),
        Human(
            human("ds-01", "sso"),
            frozenset({"human"}),
            HumanProfile(
                home=((cat.ASN_HQ, 0.5), (cat.ASN_SEATTLE_ISP, 0.5)),
                utc_offset=-8,
                apis=cat.DATA_SCIENCE_APIS,
                regions=(("us-west-2", 1.0),),
                console_share=0.4,
            ),
        ),
        Human(
            human("ds-02", "sso"),
            frozenset({"human"}),
            HumanProfile(
                home=((cat.ASN_AUSTIN_ISP, 1.0),),
                utc_offset=-6,
                apis=cat.DATA_SCIENCE_APIS,
                regions=(("us-west-2", 1.0),),
                console_share=0.4,
            ),
        ),
    ]
    teardown = rng.randint(20, days - 2) if days > 22 and rng.random() < 0.5 else None
    machines: list[Persona] = [
        CiRole(make_principal(rng, "role", "terraform-ci"), frozenset({"ci"}), teardown),
        ScannerRole(make_principal(rng, "role", "posture-scanner"), frozenset({"scanner"})),
        PipelineRole(make_principal(rng, "role", "data-pipeline"), frozenset({"workload"})),
        AppRole(make_principal(rng, "role", "orders-app"), frozenset({"workload"})),
        ServiceActivity(make_principal(rng, "role", "AWSServiceRoleForConfig"), frozenset()),
    ]
    return people + machines


class Simulation:
    """One seeded synthetic account: population, incident plan, labeled event stream."""

    def __init__(self, config: SimConfig, netmap: NetMap | None = None) -> None:
        self.config = config
        self.netmap = netmap if netmap is not None else NetMap.bundled()
        self.personas = build_population(random.Random(f"population:{config.seed}"), config.days)
        self.incidents = self._plan(random.Random(f"incidents:{config.seed}"))

    def _plan(self, rng: random.Random) -> list[Incident]:
        cfg = self.config
        incidents: list[Incident] = []
        taken: set[tuple[str, int]] = set()
        for scenario_name in cfg.scenarios:
            scenario = SCENARIOS[scenario_name]
            victims = [p for p in self.personas if p.tags & scenario.victim_tags]
            for _ in range(cfg.incidents_per_scenario):
                for _attempt in range(50):
                    victim = rng.choice(victims)
                    day = rng.randint(cfg.first_incident_day, cfg.days - 2)
                    if (victim.principal.name, day) not in taken:
                        break
                taken.add((victim.principal.name, day))
                incidents.append(
                    Incident(
                        incident_id=f"inc-{cfg.seed}-{len(incidents) + 1:02d}",
                        scenario=scenario_name,
                        victim=victim.principal.name,
                        principal=victim.principal.label,
                        day=day,
                        description=scenario.description,
                    )
                )
        return incidents

    def _day_batch(self, day: int, emit: Emitter) -> list[Labeled]:
        cfg = self.config
        start = cfg.start_epoch + day * DAY
        batch: list[Labeled] = []
        for index, persona in enumerate(self.personas):
            rng = random.Random(f"{cfg.seed}:{index}:{day}")
            emit.rng = rng
            batch.extend(
                (record, None) for record in persona.day(DayContext(day, start, rng, emit))
            )
        by_name = {p.principal.name: p for p in self.personas}
        for incident in self.incidents:
            if incident.day != day:
                continue
            rng = random.Random(f"{cfg.seed}:{incident.incident_id}")
            emit.rng = rng
            ctx = DayContext(day, start, rng, emit)
            victim = by_name[incident.victim]
            low, high = victim.active_window(ctx)
            records = SCENARIOS[incident.scenario].build(victim, ctx, rng.uniform(low, high))
            times = [_epoch(r["eventTime"]) for r in records]
            incident.start, incident.end = min(times), max(times)
            incident.events = len(records)
            incident.event_ids = [r["eventID"] for r in records]
            batch.extend((record, incident.incident_id) for record in records)
        return batch

    def stream(self) -> Iterator[Labeled]:
        """Yield ``(record, incident_id | None)`` in event-time order.

        Local working days spill across UTC midnight, so day batches overlap; a heap holds at
        most ~two days of records and releases everything older than the start of the day
        being generated (no later batch can contain anything earlier than that).
        """
        emit = Emitter(random.Random(0), self.netmap)
        heap: list[tuple[str, int, Record, str | None]] = []
        seq = 0
        for day in range(self.config.days):
            for record, label in self._day_batch(day, emit):
                heapq.heappush(heap, (record["eventTime"], seq, record, label))
                seq += 1
            horizon = _iso(self.config.start_epoch + day * DAY)
            while heap and heap[0][0] < horizon:
                _, _, record, label = heapq.heappop(heap)
                yield record, label
        while heap:
            _, _, record, label = heapq.heappop(heap)
            yield record, label

    @property
    def principals(self) -> list[str]:
        return [p.principal.label for p in self.personas]

    def metadata(self) -> dict[str, Any]:
        return {
            "config": asdict(self.config),
            "account_id": ACCOUNT_ID,
            "principals": self.principals,
            "incidents": [i.to_dict() for i in self.incidents],
        }


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def delivered(stream: Iterable[Labeled], max_delay: float, rng: random.Random) -> Iterator[Labeled]:
    """Reorder a time-ordered stream the way CloudTrail delivery does (bounded random delay)."""
    heap: list[tuple[float, int, Record, str | None]] = []
    for seq, (record, label) in enumerate(stream):
        now = _epoch(record["eventTime"])
        heapq.heappush(heap, (now + rng.uniform(0, max_delay), seq, record, label))
        while heap and heap[0][0] <= now:
            _, _, out, out_label = heapq.heappop(heap)
            yield out, out_label
    while heap:
        _, _, out, out_label = heapq.heappop(heap)
        yield out, out_label


@dataclass(slots=True)
class WriteSummary:
    events: int = 0
    labeled: int = 0
    files: int = 0


def write_dataset(
    sim: Simulation, out_dir: Path, fmt: str = "jsonl", max_delay: float = 300.0
) -> WriteSummary:
    """Write a dataset directory: events, ``labels.jsonl`` and ``incidents.json``.

    ``fmt="jsonl"`` writes ``events.jsonl`` in delivery order; ``fmt="cloudtrail"`` writes a
    gzipped ``AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/`` tree of 5-minute files.
    """
    if fmt not in {"jsonl", "cloudtrail"}:
        raise SimulationError(f"unknown format {fmt!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = WriteSummary()
    rng = random.Random(f"delivery:{sim.config.seed}")
    stream = delivered(sim.stream(), max_delay, rng)
    with (out_dir / "labels.jsonl").open("w", encoding="utf-8") as labels:
        if fmt == "jsonl":
            with (out_dir / "events.jsonl").open("w", encoding="utf-8") as events:
                for record, label in stream:
                    events.write(json.dumps(record, separators=(",", ":")) + "\n")
                    summary.events += 1
                    if label:
                        labels.write(
                            json.dumps({"event_id": record["eventID"], "incident_id": label}) + "\n"
                        )
                        summary.labeled += 1
            summary.files = 1
        else:
            summary = _write_tree(stream, out_dir, labels, summary)
    (out_dir / "incidents.json").write_text(
        json.dumps(sim.metadata(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def _write_tree(
    stream: Iterable[Labeled], out_dir: Path, labels: Any, summary: WriteSummary
) -> WriteSummary:
    buckets: dict[tuple[str, int], list[Record]] = defaultdict(list)
    bucket_span = 300

    def flush(keys: list[tuple[str, int]]) -> None:
        for region, bucket in keys:
            records = buckets.pop((region, bucket))
            stamp = datetime.fromtimestamp(bucket * bucket_span + bucket_span, tz=UTC)
            folder = (
                out_dir
                / "AWSLogs"
                / ACCOUNT_ID
                / "CloudTrail"
                / region
                / f"{stamp:%Y}"
                / f"{stamp:%m}"
                / f"{stamp:%d}"
            )
            folder.mkdir(parents=True, exist_ok=True)
            suffix = f"{stamp:%Y%m%dT%H%MZ}_{bucket % 99991:05d}.json.gz"
            name = f"{ACCOUNT_ID}_CloudTrail_{region}_{suffix}"
            with gzip.open(folder / name, "wt", encoding="utf-8") as handle:
                json.dump({"Records": records}, handle, separators=(",", ":"))
            summary.files += 1

    for record, label in stream:
        bucket = int(_epoch(record["eventTime"]) // bucket_span)
        buckets[(record["awsRegion"], bucket)].append(record)
        summary.events += 1
        if label:
            labels.write(json.dumps({"event_id": record["eventID"], "incident_id": label}) + "\n")
            summary.labeled += 1
        stale = [k for k in buckets if k[1] < bucket - 6]
        if stale:
            flush(stale)
    flush(list(buckets))
    return summary
