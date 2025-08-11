"""Command-line interface: ``trailwatch {detect,simulate,eval,tune,score,rules,config}``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import IO, Any

from trailwatch import __version__
from trailwatch.alerts import alert_to_json
from trailwatch.baseline import BaselineStore
from trailwatch.config import Config, ConfigError, parse_override, to_mapping
from trailwatch.engine import Detector
from trailwatch.evaluation import (
    ABLATIONS,
    EvalSummary,
    evaluate,
    markdown_table,
    parse_seeds,
    scenario_table,
    score_files,
    tune,
)
from trailwatch.ingest import (
    IngestStats,
    ReorderBuffer,
    discover,
    iter_file,
    iter_stream,
    ordered,
    parse_records,
)
from trailwatch.model import Severity
from trailwatch.netmap import NetMap, NetMapError
from trailwatch.rules import RULE_CLASSES
from trailwatch.sim import SCENARIOS, SimConfig, Simulation, SimulationError, write_dataset

log = logging.getLogger("trailwatch")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_ALERTS = 3


def _load_config(args: argparse.Namespace) -> Config:
    path = args.config or os.environ.get("TRAILWATCH_CONFIG")
    config = Config.load(path) if path else Config()
    overrides = dict(parse_override(item) for item in args.set or [])
    return config.with_overrides(overrides) if overrides else config


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config", help="TOML config file (default: $TRAILWATCH_CONFIG or built-in)"
    )
    parser.add_argument(
        "--set",
        action="append",
        metavar="SECTION.KEY=VALUE",
        help="override one config value, e.g. --set scoring.threshold=70 (repeatable)",
    )


def _raw_records(inputs: Sequence[str], stats: IngestStats) -> Iterator[Any]:
    if list(inputs) == ["-"]:
        try:
            yield from iter_stream(sys.stdin, stats, "<stdin>")
        except UnicodeDecodeError as exc:
            # Stop reading, but still drain the reorder buffer and write state for what was read.
            stats.bad_files += 1
            log.error("<stdin>: stopping at undecodable input: %s", exc)
        return
    for path in discover(Path(p) for p in inputs):
        yield from iter_file(path, stats)


def _open_out(target: str) -> IO[str]:
    if target == "-":
        return sys.stdout
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def cmd_detect(args: argparse.Namespace) -> int:
    config = _load_config(args)
    netmap = NetMap.from_csv(args.netmap) if args.netmap else NetMap.bundled()
    baseline = None
    if args.state_in:
        data = json.loads(Path(args.state_in).read_text(encoding="utf-8"))
        baseline = BaselineStore.from_dict(data, config.baseline)
    detector = Detector(config, netmap, baseline=baseline)
    stats = IngestStats()
    buffer = ReorderBuffer(config.ingest.max_lateness_seconds, config.ingest.max_buffer, stats)
    events = ordered(parse_records(_raw_records(args.inputs, stats), stats), buffer)
    min_severity = Severity.parse(args.min_severity)
    worst = Severity.INFO
    emitted = 0
    out = _open_out(args.out)
    try:
        for alert in detector.run(events):
            if alert.severity < min_severity:
                continue
            out.write(alert_to_json(alert) + "\n")
            out.flush()
            emitted += 1
            worst = max(worst, alert.severity)
    finally:
        if out is not sys.stdout:
            out.close()
    if args.state_out:
        Path(args.state_out).write_text(json.dumps(detector.baseline.to_dict()), encoding="utf-8")
    summary = {
        "ingest": {k: getattr(stats, k) for k in stats.__slots__},
        "engine": detector.stats.to_dict(),
        "dedup": {"suppressed": detector.dedup.suppressed, "escalated": detector.dedup.escalated},
        "state": detector.state_sizes(),
        "alerts_written": emitted,
    }
    if args.stats:
        print(json.dumps(summary, indent=2), file=sys.stderr)
    else:
        log.info(
            "processed %d events, %d findings, wrote %d alerts",
            detector.stats.events,
            detector.stats.findings,
            emitted,
        )
    if args.fail_on and emitted and worst >= Severity.parse(args.fail_on):
        return EXIT_ALERTS
    return EXIT_OK


def cmd_simulate(args: argparse.Namespace) -> int:
    config = SimConfig(
        seed=args.seed,
        days=args.days,
        start=args.start,
        incidents_per_scenario=args.incidents_per_scenario,
        incident_start_day=args.incident_start_day,
        scenarios=tuple(args.scenario) if args.scenario else tuple(SCENARIOS),
    )
    sim = Simulation(config)
    summary = write_dataset(sim, Path(args.out), args.format, args.max_delay)
    print(
        f"wrote {summary.events} events ({summary.labeled} labeled, "
        f"{len(sim.incidents)} incidents, {len(sim.personas)} principals) "
        f"in {summary.files} file(s) to {args.out}"
    )
    for incident in sim.incidents:
        print(
            f"  {incident.incident_id}  day {incident.day:>3}  {incident.scenario:<24} "
            f"victim={incident.victim:<16} events={incident.events}"
        )
    return EXIT_OK


def _print_summary(title: str, summary: EvalSummary) -> None:
    print(f"\n## {title}\n")
    print(markdown_table({title: summary}))
    print()
    print(scenario_table(summary))
    print(f"\nfalse alerts by rule: {summary.false_alerts_by_rule}")
    print(f"end-to-end events/s (simulate + deliver + detect): {summary.events_per_second}")


def cmd_eval(args: argparse.Namespace) -> int:
    config = _load_config(args)
    seeds = parse_seeds(args.seeds)
    variants = ABLATIONS if args.ablations else {"full": {}}
    summaries: dict[str, EvalSummary] = {}
    for name, overrides in variants.items():
        variant_config = config.with_overrides(overrides) if overrides else config
        summaries[name] = evaluate(
            seeds, args.days, variant_config, incidents_per_scenario=args.incidents_per_scenario
        )
        log.info("variant %s done", name)
    print(f"held-out seeds {seeds}, {args.days} days each\n")
    print(markdown_table(summaries))
    _print_summary("full", summaries["full"])
    if args.json:
        payload = {
            "seeds": seeds,
            "days": args.days,
            "config": to_mapping(config),
            "variants": {k: v.to_dict() for k, v in summaries.items()},
        }
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return EXIT_OK


def _parse_grid(items: Iterable[str]) -> dict[str, list[Any]]:
    grid: dict[str, list[Any]] = {}
    for item in items:
        key, _, values = item.partition("=")
        if not values:
            raise ConfigError(f"grid entry must look like section.key=v1,v2: {item!r}")
        grid[key.strip()] = [parse_override(f"{key}={v}")[1] for v in values.split(",")]
    return grid


def cmd_tune(args: argparse.Namespace) -> int:
    config = _load_config(args)
    grid = _parse_grid(args.grid)
    best, rows = tune(parse_seeds(args.seeds), args.days, config, grid, args.budget)
    best_ids = {id(row) for row in best}
    print("| overrides | recall | precision | alerts | false alerts/day |")
    print("|---|---:|---:|---:|---:|")
    for row in rows:
        s = row.summary
        marker = " **(best)**" if id(row) in best_ids else ""
        print(
            f"| {row.overrides}{marker} | {s.recall:.3f} | {s.precision:.3f} | {s.alerts} | "
            f"{s.false_alerts_per_day:.3f} |"
        )
    print(f"\nbest within {args.budget} false alerts/day ({len(best)} tied):")
    for row in best:
        print(f"  {row.overrides}")
    return EXIT_OK


def cmd_score(args: argparse.Namespace) -> int:
    dataset = Path(args.dataset)
    result = score_files(Path(args.alerts), dataset / "labels.jsonl", dataset / "incidents.json")
    print(json.dumps(result, indent=2))
    return EXIT_OK


def cmd_rules(_args: argparse.Namespace) -> int:
    for cls in RULE_CLASSES:
        print(f"{cls.rule_id}  [{', '.join(cls.techniques)}]")
        print(f"    {cls.description}\n")
    return EXIT_OK


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return repr(value)


def dump_toml(config: Config) -> str:
    lines = ["# trailwatch configuration (generated by `trailwatch config`)."]
    for section, values in to_mapping(config).items():
        lines.append(f"\n[{section}]")
        lines.extend(f"{key} = {_toml_value(value)}" for key, value in values.items())
    return "\n".join(lines) + "\n"


def cmd_config(args: argparse.Namespace) -> int:
    sys.stdout.write(dump_toml(_load_config(args)))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trailwatch", description="CloudTrail identity-threat detection."
    )
    parser.add_argument("--version", action="version", version=f"trailwatch {__version__}")
    parser.add_argument(
        "--log-level",
        default=os.environ.get("TRAILWATCH_LOG_LEVEL", "WARNING"),
        help="logging level (default: $TRAILWATCH_LOG_LEVEL or WARNING)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("detect", help="run detection over CloudTrail files/dirs or stdin")
    p.add_argument("inputs", nargs="+", help="files, directories, or - for JSON lines on stdin")
    p.add_argument("--out", default="-", help="alerts JSONL path (default: stdout)")
    p.add_argument("--netmap", help="CSV network map replacing the bundled synthetic one")
    p.add_argument("--state-in", help="baseline snapshot to resume from")
    p.add_argument("--state-out", help="write the baseline snapshot here when done")
    p.add_argument("--min-severity", default="info", help="only write alerts at or above this")
    p.add_argument("--fail-on", help="exit 3 if any written alert is at or above this severity")
    p.add_argument("--stats", action="store_true", help="print run statistics to stderr")
    _add_config_args(p)
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("simulate", help="generate a labeled synthetic CloudTrail dataset")
    p.add_argument("--out", required=True, help="output directory")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--start", default="2026-01-05", help="first simulated day (UTC date)")
    p.add_argument("--format", choices=["jsonl", "cloudtrail"], default="jsonl")
    p.add_argument("--incidents-per-scenario", type=int, default=2)
    p.add_argument(
        "--incident-start-day", type=int, help="first day incidents may occur (default: 21)"
    )
    p.add_argument("--scenario", action="append", choices=sorted(SCENARIOS))
    p.add_argument("--max-delay", type=float, default=300.0, help="max delivery delay (s)")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("eval", help="evaluate on simulated seeds (precision/recall)")
    p.add_argument("--seeds", default="1001-1005")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--incidents-per-scenario", type=int, default=2)
    p.add_argument("--ablations", action="store_true", help="also run ablation variants")
    p.add_argument("--json", help="write full results JSON here")
    _add_config_args(p)
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("tune", help="grid-search parameters on tuning seeds")
    p.add_argument("--seeds", default="1-3")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--budget", type=float, default=0.05, help="max false alerts per day")
    p.add_argument("--grid", action="append", required=True, metavar="SECTION.KEY=V1,V2")
    _add_config_args(p)
    p.set_defaults(func=cmd_tune)

    p = sub.add_parser("score", help="score an alerts JSONL file against a simulated dataset")
    p.add_argument("--alerts", required=True)
    p.add_argument("--dataset", required=True, help="directory written by `simulate`")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("rules", help="list detection rules")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("config", help="print the effective configuration as TOML")
    _add_config_args(p)
    p.set_defaults(func=cmd_config)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.WARNING),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        result: int = args.func(args)
    except (ConfigError, SimulationError, NetMapError, ValueError) as exc:
        print(f"trailwatch: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"trailwatch: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return result


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
