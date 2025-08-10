#!/usr/bin/env bash
# Offline end-to-end demo: simulate a labeled account, detect, score, and replay the fixture.
set -euo pipefail
OUT="${DEMO_OUT:-demo-out}"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "== 1. Simulate 45 days of a 19-principal account (seed 7) as a gzipped CloudTrail tree"
uv run trailwatch simulate --out "$OUT/data" --seed 7 --days 45 --format cloudtrail

echo
echo "== 2. Detect (streaming, reorder buffer, baselines, rules, risk scoring, dedup)"
uv run trailwatch detect "$OUT/data/AWSLogs" --out "$OUT/alerts.jsonl" \
  --state-out "$OUT/baseline.json" --stats 2> "$OUT/stats.json"
uv run python -c "import json,sys; s=json.load(open(sys.argv[1])); print(json.dumps({k: s[k] for k in ('ingest','dedup','alerts_written')}, indent=1))" "$OUT/stats.json"

echo
echo "== 3. Alerts (TP = cites an injected incident event; FP = benign activity)"
uv run python scripts/show_alerts.py "$OUT/alerts.jsonl" --labels "$OUT/data/labels.jsonl"

echo
echo "== 4. Score against ground truth"
uv run trailwatch score --alerts "$OUT/alerts.jsonl" --dataset "$OUT/data"

echo
echo "== 5. The first impossible-travel alert in full (JSON format)"
grep -m 1 '"rule_id":"impossible_travel"' "$OUT/alerts.jsonl" | uv run python -m json.tool

echo
echo "== 6. Hand-authored CloudTrail fixture (phished no-MFA console user -> backdoor -> StopLogging)"
uv run trailwatch detect fixtures/cloudtrail --out "$OUT/fixture-alerts.jsonl"
uv run python scripts/show_alerts.py "$OUT/fixture-alerts.jsonl"
