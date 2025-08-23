# Design decisions

Key design decisions in trailwatch, each with the reasoning and what it would cost if it turned out wrong. Format: `- <decision> — <why> — <cost if wrong>`.

## Scope and architecture

- Python 3.12 standard library only at runtime (no pandas/numpy) — a streaming per-event detector gains nothing from vectorisation and zero dependencies make it trivial to run anywhere — cost if wrong: slower than a compiled implementation (~49k events/s measured), acceptable for a single account.
- management events only — they are what the default trail records and where identity attacks appear first — cost if wrong: misses data-exfiltration patterns visible only in data events.
- rules evaluate before the baseline learns the current event — otherwise "first use of X" could never fire — cost if wrong: none known.
- skip `AWSService` identities entirely — services acting on the account's behalf are not identity threats and dominate volume in real trails — cost if wrong: misses abuse that is only visible through service-linked calls.
- role sessions share one baseline per role ARN, but IAM Identity Center (SSO) sessions are per role + session name — machine-role session names are random, SSO session names are the person — cost if wrong: a non-SSO role used by several humans gets one blended baseline.
- baselines use user-agent families and ASNs, not raw strings and IPs — SDK upgrades and DHCP churn would otherwise be "new" weekly — cost if wrong: an attacker using the same family/ASN as the victim is not novel.
- late events (older than the reorder watermark) are processed, not dropped — dropping security events is worse than slightly wrong ordering — cost if wrong: a late event can produce a mis-ordered stateful decision (rules guard against negative time deltas).
- CloudTrail directories are ordered by the timestamp embedded in file names, not by path — path order replays one region's entire history before the next; found when the first file-based run produced extra alerts vs. the in-memory run — cost if wrong: files from other producers fall back to name order.
- streamed JSONL alerts are written at emission and not re-emitted when duplicates fold in later — keeps output append-only and small — cost if wrong: downstream consumers do not see final counts/evidence (documented in README limitations; in-memory consumers do).

## Detection logic

- the console no-MFA rule only trusts `MFAUsed` for IAMUser and Root identities — federated (SSO/SAML) sign-ins always report `MFAUsed: No` because MFA happens at the IdP — cost if wrong: a federated session without IdP MFA is not flagged by this rule.
- impossible travel is suppressed when both ASNs are familiar to the principal (instead of a VPN allowlist) — corporate VPN egress and split tunnels are learned per principal without hand-maintained lists — cost if wrong: an attacker who repeatedly uses a network until familiar is suppressed (baseline poisoning).
- impossible-travel severity is reduced one level for VPN or mobile networks and one level before warm-up — relayed or coarse geolocation is weaker evidence — cost if wrong: an attacker using a commercial VPN gets medium (risk-scored) rather than high.
- thresholds 1,000 km/h and 500 km minimum distance — above airliner cruise speed; below 500 km city-level geolocation noise dominates — cost if wrong: very fast regional hops are missed.
- an access key created by a role counts as "for another principal" — roles cannot own access keys, so any key a role creates is for someone else — cost if wrong: none known.
- onboarding pattern (caller created the target user within the hour) lowers key-creation severity by one — admin onboarding of new hires was the dominant false positive on development seeds — cost if wrong: an attacker who creates a backdoor user and key in one session gets one level lower (still alerted via no-MFA escalation or the console rule in the modelled scenarios).
- `access_keys.routine_min_weight` lowered from 2.0 to 1.5 during development (seed 1) — admins creating keys roughly weekly crossed 2.0 only after the fourth creation — cost if wrong: a principal that created keys twice recently is treated as routine.
- enumeration suppression compares against the principal's peak from previous days only, decaying 2%/day, with a 1.25x margin — posture scanners and Terraform legitimately make dozens of distinct discovery calls per run — cost if wrong: an attacker using a scanner's credentials at the scanner's volume is suppressed (denial storms still fire).
- enumeration fires once per window per principal unless severity rises — avoids a finding per event during a burst while still allowing a denial storm to escalate when volume follows — cost if wrong: none known.
- novelty requires warm-up (>= 7 days and >= 50 events) except the penetration-testing distribution UA, which is high always — every principal would otherwise alert on day one — cost if wrong: an attacker using a brand-new principal is only caught by stateful rules.
- severity weights info 0 / low 10 / medium 25 / high 50 / critical 80 are fixed, not learned — transparent and easy to reason about; learned weights would need far more labeled data than the simulator provides honestly — cost if wrong: suboptimal combination of weak signals.
- risk alerts fold into an open rule alert of equal or higher severity for the same principal — the analyst already has a case open for that principal — cost if wrong: the risk context is only visible inside the existing alert.
- dedup TTL is sliding on `last_seen` (12 h) — a continuous campaign remains one alert — cost if wrong: a very long, steady campaign never re-alerts (escalations still do).
- no trail-name allowlist by default (`logging_tamper.allowlist_trail_prefixes = []`) — allowlisting audit-trail deletion is an organisational decision, so the benign sandbox teardown remains a visible false positive — cost if wrong: about one false critical per two simulated quarters.
- a file that cannot be read to the end (`OSError` incl. `gzip.BadGzipFile`, `EOFError` from truncated gzip, `zlib.error`, `UnicodeDecodeError`) is logged at ERROR, counted in `ingest.bad_files` and skipped; the run continues, the reorder buffer is still flushed and `--state-out` is still written; records already read from that file before the failure are kept — synced S3 trees routinely contain partial downloads and stray files, and aborting lost up to 15 minutes of buffered events plus every later file — cost if wrong: a damaged file's unread remainder is silently missing from detection apart from the log line and the counter; the exit code does not change.
- undecodable bytes on stdin stop reading stdin (a text stream cannot resynchronise) but are handled the same way otherwise (counted as `bad_files`, buffer flushed, state written) — consistent with the per-file rule — cost if wrong: input after the bad bytes is not processed.
- non-UTF-8 input is not decoded with a fallback codec — CloudTrail is UTF-8 by specification, so non-UTF-8 bytes mean a damaged or foreign file — cost if wrong: a re-encoded (e.g. Latin-1) export is skipped rather than read.

## Evaluation protocol

- seeds 1-3 are development/tuning seeds; seeds 1001-1005 are held out and were run once, after code and configuration were frozen — avoids reporting numbers on the data used to make decisions — cost if wrong: none; the development seeds' numbers are visible in `eval/tune.md` for comparison.
- the demo uses seed 7 (neither tuning nor held-out) — keeps demo output independent of both — cost if wrong: none.
- tuning objective = maximise recall subject to <= 0.05 false alerts/day, then precision, then fewer alerts; all tied points are reported — 0.05/day is one false alert every 20 days for a 19-principal account, roughly what one analyst would tolerate for one small account — cost if wrong: a different budget picks a different threshold.
- among the eight tied-best tuning points the shipped defaults are threshold 60 and half-life 6 h (the lowest tied threshold, middle half-life) — prefer the most sensitive threshold and a memory long enough to link a working session's signals — cost if wrong: on real data a different tied point may generalise better; all eight are listed.
- an alert counts as a true positive if it cites any event of an incident (evidence or folded findings) — matches how an analyst would triage it — cost if wrong: a benign alert that happens to absorb an incident finding is credited (possible only for the same principal within the TTL).
- include a `low_and_slow` scenario the design cannot catch — keeps the headline recall honest and shows the boundary of baseline-based detection — cost if wrong: recall looks worse than a curated scenario set would.
- 12 incidents per 90-day account (2 per scenario, after day 21) — enough to measure per-scenario recall over 5 held-out seeds (10 incidents each) without making attacks the majority of anomalies — cost if wrong: real incident base rates are much lower, so real precision would be lower at the same false-alert rate.
- `incident_start_day` defaults to 21 (or a third of the run for short simulations) — principals need a warm-up baseline before an attack is meaningful — cost if wrong: attacks on day-one principals are under-represented.

## Engineering

- `config/default.toml` is a generated dump of the built-in defaults, and a test enforces equality — one source of truth for defaults, still a readable reference file — cost if wrong: none.
- coverage gate 90% (measured 98.7%) on line + branch over the whole package including the simulator — the simulator is part of the deliverable — cost if wrong: none.
- no `make integration` target — there is no external service to integrate with (no Docker, no network needed) — cost if wrong: none.
- the CI workflow mirrors `make check` and `make demo`; it runs on every push to `main` — cost if wrong: a CI-only environment difference (toolchain version, OS) would fail the run.
