"""Print a compact, human-readable table of an alerts JSONL file.

Usage: uv run python scripts/show_alerts.py ALERTS.jsonl [--labels DATASET/labels.jsonl]
With --labels, each alert is marked TP (cites an injected incident event) or FP.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alerts", type=Path)
    parser.add_argument("--labels", type=Path)
    args = parser.parse_args()
    labels: dict[str, str] = {}
    if args.labels:
        for line in args.labels.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            labels[row["event_id"]] = row["incident_id"]
    for line in args.alerts.read_text(encoding="utf-8").splitlines():
        alert = json.loads(line)
        ids = {e["event_id"] for e in alert["evidence"]}
        for finding in alert["findings"]:
            ids.update(finding["evidence"])
        hits = sorted({labels[i] for i in ids if i in labels})
        verdict = ""
        if args.labels:
            verdict = f"TP {','.join(hits)}" if hits else "FP"
        who = alert["principal"].rsplit(":", 1)[-1][:28]
        print(
            f"{alert['created']}  {alert['severity']:<8} {alert['rule_id']:<28} "
            f"{who:<28} {alert['title'][:58]:<58} {verdict}"
        )


if __name__ == "__main__":
    main()
