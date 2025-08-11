"""Evaluation against labeled simulations, threshold tuning, and ablations.

Protocol (see ``DECISIONS.md``): parameters are tuned only on *tuning seeds*; the numbers in the
README come from disjoint *held-out seeds* run once with the committed configuration.

Matching: an alert is a true positive if any event it cites (alert evidence or the evidence of
any finding folded into it) belongs to an injected incident; an incident is detected if at least
one alert cites one of its events. Time to detect is measured in event time from the incident's
first event to the moment the citing alert fired (or absorbed the citing finding).
"""

from __future__ import annotations

import itertools
import json
import random
import statistics
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trailwatch.config import Config
from trailwatch.engine import Detector
from trailwatch.ingest import IngestStats, ReorderBuffer, ordered, parse_records
from trailwatch.model import Alert
from trailwatch.netmap import NetMap
from trailwatch.sim import SimConfig, Simulation, delivered

DAY = 86_400.0


@dataclass(slots=True)
class SeedResult:
    seed: int
    days: int
    events: int
    incidents: int
    detected: int
    alerts: int
    true_alerts: int
    seconds: float
    scenario_total: dict[str, int] = field(default_factory=dict)
    scenario_detected: dict[str, int] = field(default_factory=dict)
    detect_seconds: list[float] = field(default_factory=list)
    false_alerts_by_rule: dict[str, int] = field(default_factory=dict)
    true_alerts_by_rule: dict[str, int] = field(default_factory=dict)
    missed: list[str] = field(default_factory=list)

    @property
    def false_alerts(self) -> int:
        return self.alerts - self.true_alerts


@dataclass(slots=True)
class EvalSummary:
    seeds: list[int]
    days: int
    events: int
    incidents: int
    detected: int
    alerts: int
    true_alerts: int
    precision: float
    recall: float
    alerts_per_day: float
    false_alerts_per_day: float
    median_minutes_to_detect: float | None
    events_per_second: float
    recall_by_scenario: dict[str, float]
    false_alerts_by_rule: dict[str, int]
    true_alerts_by_rule: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_seeds(text: str) -> list[int]:
    """``"1-3"`` -> ``[1, 2, 3]``; ``"1,5,9"`` -> ``[1, 5, 9]``; ranges and lists combine."""
    seeds: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        low, sep, high = part.partition("-")
        try:
            if sep:
                first, last = int(low), int(high)
                if last < first:
                    raise ValueError
                seeds.extend(range(first, last + 1))
            else:
                seeds.append(int(part))
        except ValueError as exc:
            raise ValueError(f"invalid seed list {text!r}") from exc
    if not seeds:
        raise ValueError("no seeds given")
    return seeds


def run_seed(
    seed: int,
    days: int,
    config: Config,
    *,
    incidents_per_scenario: int = 2,
    max_delay: float = 300.0,
    netmap: NetMap | None = None,
) -> SeedResult:
    """Simulate one seed, run the detector over the delivered stream, and score the alerts."""
    netmap = netmap if netmap is not None else NetMap.bundled()
    sim = Simulation(
        SimConfig(seed=seed, days=days, incidents_per_scenario=incidents_per_scenario), netmap
    )
    labels: dict[str, str] = {}

    def records() -> Iterator[dict[str, Any]]:
        rng = random.Random(f"delivery:{seed}")
        for record, label in delivered(sim.stream(), max_delay, rng):
            if label is not None:
                labels[record["eventID"]] = label
            yield record

    stats = IngestStats()
    buffer = ReorderBuffer(config.ingest.max_lateness_seconds, config.ingest.max_buffer, stats)
    detector = Detector(config, netmap)
    started = time.perf_counter()
    alerts = list(detector.run(ordered(parse_records(records(), stats), buffer)))
    seconds = time.perf_counter() - started
    return score_alerts(sim, alerts, labels, seed, days, stats.events, seconds)


def score_alerts(
    sim: Simulation,
    alerts: Sequence[Alert],
    labels: dict[str, str],
    seed: int,
    days: int,
    events: int,
    seconds: float,
) -> SeedResult:
    starts = {inc.incident_id: inc.start for inc in sim.incidents}
    detected_at: dict[str, float] = {}
    true_by_rule: Counter[str] = Counter()
    false_by_rule: Counter[str] = Counter()
    for alert in alerts:
        hits = {labels[eid] for eid in alert.evidence_ids() if eid in labels}
        if not hits:
            false_by_rule[alert.rule_id] += 1
            continue
        true_by_rule[alert.rule_id] += 1
        for finding in alert.findings:
            for incident in {labels[e] for e in finding.evidence if e in labels}:
                when = max(alert.created, finding.time)
                detected_at[incident] = min(detected_at.get(incident, when), when)
        for incident in hits:
            detected_at.setdefault(incident, alert.created)
    scenario_total: Counter[str] = Counter(inc.scenario for inc in sim.incidents)
    scenario_detected: Counter[str] = Counter(
        inc.scenario for inc in sim.incidents if inc.incident_id in detected_at
    )
    return SeedResult(
        seed=seed,
        days=days,
        events=events,
        incidents=len(sim.incidents),
        detected=len(detected_at),
        alerts=len(alerts),
        true_alerts=sum(true_by_rule.values()),
        seconds=seconds,
        scenario_total=dict(scenario_total),
        scenario_detected=dict(scenario_detected),
        detect_seconds=sorted(max(0.0, t - starts[i]) for i, t in detected_at.items()),
        false_alerts_by_rule=dict(false_by_rule),
        true_alerts_by_rule=dict(true_by_rule),
        missed=[i.incident_id for i in sim.incidents if i.incident_id not in detected_at],
    )


def summarize(results: Sequence[SeedResult]) -> EvalSummary:
    if not results:
        raise ValueError("no results to summarise")
    days = sum(r.days for r in results)
    alerts = sum(r.alerts for r in results)
    true_alerts = sum(r.true_alerts for r in results)
    incidents = sum(r.incidents for r in results)
    detected = sum(r.detected for r in results)
    totals: Counter[str] = Counter()
    hits: Counter[str] = Counter()
    false_by_rule: Counter[str] = Counter()
    true_by_rule: Counter[str] = Counter()
    for r in results:
        totals.update(r.scenario_total)
        hits.update(r.scenario_detected)
        false_by_rule.update(r.false_alerts_by_rule)
        true_by_rule.update(r.true_alerts_by_rule)
    detect = [s for r in results for s in r.detect_seconds]
    seconds = sum(r.seconds for r in results)
    events = sum(r.events for r in results)
    return EvalSummary(
        seeds=[r.seed for r in results],
        days=days,
        events=events,
        incidents=incidents,
        detected=detected,
        alerts=alerts,
        true_alerts=true_alerts,
        precision=round(true_alerts / alerts, 4) if alerts else 1.0,
        recall=round(detected / incidents, 4) if incidents else 1.0,
        alerts_per_day=round(alerts / days, 4),
        false_alerts_per_day=round((alerts - true_alerts) / days, 4),
        median_minutes_to_detect=round(statistics.median(detect) / 60, 2) if detect else None,
        events_per_second=round(events / seconds) if seconds > 0 else 0.0,
        recall_by_scenario={k: round(hits[k] / totals[k], 4) for k in sorted(totals)},
        false_alerts_by_rule=dict(sorted(false_by_rule.items())),
        true_alerts_by_rule=dict(sorted(true_by_rule.items())),
    )


def evaluate(seeds: Sequence[int], days: int, config: Config, **kwargs: Any) -> EvalSummary:
    netmap = NetMap.bundled()
    return summarize([run_seed(s, days, config, netmap=netmap, **kwargs) for s in seeds])


ABLATIONS: dict[str, dict[str, Any]] = {
    "full": {},
    "no_familiarity_suppression": {"baseline.suppress_familiar": False},
    "no_behavioral_novelty": {"novelty.enabled": False},
    "no_risk_scoring": {"scoring.threshold": 1e9},
}


@dataclass(slots=True)
class TuneRow:
    overrides: dict[str, Any]
    summary: EvalSummary


def tune(
    seeds: Sequence[int],
    days: int,
    base: Config,
    grid: dict[str, list[Any]],
    false_alert_budget: float,
) -> tuple[list[TuneRow], list[TuneRow]]:
    """Grid-search ``grid`` on ``seeds``; return ``(tied_best, all_rows)``.

    Best = maximum recall within the false-alert budget, then precision, then fewest alerts.
    Every grid point that ties on all three is returned, because choosing among equally good
    points is a judgement call that should be recorded rather than hidden in iteration order.
    If no point meets the budget, the points with the fewest false alerts per day win.
    """
    keys = sorted(grid)
    rows: list[TuneRow] = []
    for values in itertools.product(*(grid[k] for k in keys)):
        overrides = dict(zip(keys, values, strict=True))
        rows.append(TuneRow(overrides, evaluate(seeds, days, base.with_overrides(overrides))))
    within = [r for r in rows if r.summary.false_alerts_per_day <= false_alert_budget]
    key = _quality if within else _fewest_false
    pool = within or rows
    top = max(key(r) for r in pool)
    return [r for r in pool if key(r) == top], rows


def _quality(row: TuneRow) -> tuple[float, float, float]:
    return (row.summary.recall, row.summary.precision, float(-row.summary.alerts))


def _fewest_false(row: TuneRow) -> tuple[float, float, float]:
    return (-row.summary.false_alerts_per_day, row.summary.recall, row.summary.precision)


def markdown_table(summaries: dict[str, EvalSummary]) -> str:
    """Render named summaries as a GitHub-flavoured markdown table."""
    lines = [
        "| variant | incidents | detected | recall | alerts | precision | alerts/day "
        "| false alerts/day | median TTD (min) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, s in summaries.items():
        ttd = "-" if s.median_minutes_to_detect is None else f"{s.median_minutes_to_detect:.1f}"
        lines.append(
            f"| {name} | {s.incidents} | {s.detected} | {s.recall:.3f} | {s.alerts} | "
            f"{s.precision:.3f} | {s.alerts_per_day:.3f} | {s.false_alerts_per_day:.3f} | {ttd} |"
        )
    return "\n".join(lines)


def scenario_table(summary: EvalSummary) -> str:
    lines = ["| scenario | recall |", "|---|---:|"]
    lines.extend(f"| {k} | {v:.3f} |" for k, v in summary.recall_by_scenario.items())
    return "\n".join(lines)


def score_files(alerts_path: Path, labels_path: Path, incidents_path: Path) -> dict[str, Any]:
    """Score a JSONL alerts file (as written by ``trailwatch detect``) against a dataset.

    Uses only what the alert JSON carries (evidence and finding evidence ids), which proves the
    output format is sufficient for triage tooling to tie alerts back to events.
    """
    labels: dict[str, str] = {}
    with labels_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                labels[row["event_id"]] = row["incident_id"]
    meta = json.loads(incidents_path.read_text(encoding="utf-8"))
    incidents = {i["incident_id"]: i for i in meta["incidents"]}
    alerts = true_alerts = 0
    detected: set[str] = set()
    for line in alerts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        alert = json.loads(line)
        alerts += 1
        ids = {e["event_id"] for e in alert["evidence"]}
        for finding in alert["findings"]:
            ids.update(finding["evidence"])
        hits = {labels[i] for i in ids if i in labels}
        if hits:
            true_alerts += 1
            detected |= hits
    days = int(meta["config"]["days"])
    return {
        "alerts": alerts,
        "true_alerts": true_alerts,
        "precision": round(true_alerts / alerts, 4) if alerts else 1.0,
        "incidents": len(incidents),
        "detected": len(detected),
        "recall": round(len(detected) / len(incidents), 4) if incidents else 1.0,
        "alerts_per_day": round(alerts / days, 4),
        "missed": sorted(
            f"{k} ({v['scenario']})" for k, v in incidents.items() if k not in detected
        ),
    }
