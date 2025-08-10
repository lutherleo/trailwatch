"""Throughput and bounded-memory benchmark.

Usage: uv run python scripts/bench.py [--days 90] [--seed 42]

1. Throughput: generate one simulated account (in memory, untimed), then time parse + detect.
2. Bounded state: stream synthetic events from many distinct principals through a detector with
   small caps and report peak traced memory, which must stay flat as the principal count grows.
"""

from __future__ import annotations

import argparse
import platform
import time
import tracemalloc
from typing import Any

from trailwatch.config import Config
from trailwatch.engine import Detector
from trailwatch.ingest import IngestStats, parse_records
from trailwatch.parse import parse_record
from trailwatch.sim import SimConfig, Simulation


def throughput(seed: int, days: int) -> dict[str, Any]:
    records = [record for record, _ in Simulation(SimConfig(seed=seed, days=days)).stream()]
    detector = Detector(Config())
    stats = IngestStats()
    start = time.perf_counter()
    alerts = sum(1 for _ in detector.run(parse_records(records, stats)))
    elapsed = time.perf_counter() - start
    return {"events": stats.events, "seconds": elapsed, "alerts": alerts}


def bounded(principals: int, events: int) -> float:
    config = Config().with_overrides(
        {
            "baseline.max_principals": 1000,
            "state.max_rule_principals": 1000,
            "dedup.max_entries": 1000,
        }
    )
    detector = Detector(config)
    template: dict[str, Any] = {
        "eventVersion": "1.08",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "100.64.0.10",
        "userAgent": "aws-cli/2.15.30",
        "recipientAccountId": "111122223333",
    }
    tracemalloc.start()
    for i in range(events):
        user = f"user-{i % principals}"
        record = dict(template)
        record["eventID"] = f"e{i}"
        record["eventTime"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(1_767_225_600 + i))
        record["userIdentity"] = {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::111122223333:user/{user}",
            "accountId": "111122223333",
            "userName": user,
        }
        detector.process(parse_record(record))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1e6


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(f"python {platform.python_version()} on {platform.machine()} {platform.system()}")
    result = throughput(args.seed, args.days)
    rate = result["events"] / result["seconds"]
    print(
        f"throughput: {result['events']} events ({args.days} simulated days) in "
        f"{result['seconds']:.2f} s = {rate:,.0f} events/s, {result['alerts']} alerts"
    )
    print("bounded state (caps = 1000 principals, 60k events):")
    for principals in (1_000, 10_000, 60_000):
        peak = bounded(principals, 60_000)
        print(f"  {principals:>6} distinct principals -> peak traced memory {peak:6.1f} MB")


if __name__ == "__main__":
    main()
