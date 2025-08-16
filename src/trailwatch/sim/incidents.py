"""Labeled attack scenarios injected into the benign stream.

Each scenario is a short, realistic sequence of management-API calls an intruder makes after
obtaining a principal's credentials. Every record a scenario emits is labeled with the incident
id (in a sidecar labels file, never inside the record, so the detector cannot cheat).

The scenarios are written from public descriptions of cloud intrusion tradecraft (MITRE ATT&CK
for IaaS) at the level of "which API calls appear in CloudTrail"; they contain no exploit code
and touch nothing outside the simulator.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from trailwatch.sim import catalog as cat
from trailwatch.sim.catalog import Api
from trailwatch.sim.personas import Automation, DayContext, Persona
from trailwatch.sim.records import Emitter

Record = dict[str, Any]
DETECTOR_ID = "12abc34d567e8fa901bc2d34e56789f0"
DENIABLE_SERVICES = frozenset({"iam", "organizations", "guardduty", "kms", "secretsmanager", "rds"})


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    description: str
    victim_tags: frozenset[str]
    build: Callable[[Persona, DayContext, float], list[Record]]


def _attacker(rng: random.Random, emit: Emitter) -> tuple[int, str]:
    asn = rng.choice(cat.HOSTILE_ASNS)
    return asn, emit.ip_in(asn)


def _attacker_ua(rng: random.Random, version: int) -> str:
    family = rng.choices(
        ["boto3", "aws-cli", "offensive-distro", "scripted-http"], [0.35, 0.3, 0.15, 0.2]
    )[0]
    return cat.user_agent(family, version)


def stolen_access_key(victim: Persona, ctx: DayContext, start: float) -> list[Record]:
    """Leaked long-term key used from attacker infrastructure: recon, region sweep, impact."""
    rng, emit, who = ctx.rng, ctx.emit, victim.principal
    _, ip = _attacker(rng, emit)
    ua = _attacker_ua(rng, rng.randrange(10, 40))
    t = start
    records = [emit.record(who, t, ("sts", "GetCallerIdentity", True), "us-east-1", ip, ua)]
    for api in rng.sample(cat.RECON_APIS, rng.randint(6, 14)):
        t += rng.uniform(3, 40)
        error = "AccessDenied" if api[0] in DENIABLE_SERVICES and rng.random() < 0.3 else None
        records.append(emit.record(who, t, api, "us-east-1", ip, ua, error=error))
    for region in rng.sample(cat.REGIONS, rng.randint(2, 4)):
        t += rng.uniform(2, 20)
        records.append(emit.record(who, t, ("ec2", "DescribeInstances", True), region, ip, ua))
    if rng.random() < 0.5:
        region = rng.choice(cat.REGIONS[4:])
        t += rng.uniform(20, 120)
        records.append(
            emit.record(
                who,
                t,
                ("ec2", "RunInstances", False),
                region,
                ip,
                ua,
                params={"instanceType": "p3.16xlarge", "minCount": 10, "maxCount": 10},
            )
        )
    return records


def console_no_mfa_privesc(victim: Persona, ctx: DayContext, start: float) -> list[Record]:
    """Phished console password (no MFA) -> backdoor admin user with keys."""
    rng, emit, who = ctx.rng, ctx.emit, victim.principal
    asn = rng.choice((*cat.HOSTILE_ASNS, cat.ASN_LONDON_HOTEL))
    ip = emit.ip_in(asn)
    browser = cat.user_agent("browser", rng.randrange(1, 9))
    console = cat.user_agent("console", 0)
    backdoor = f"svc-backup-{rng.randrange(10, 99)}"
    t = start
    records = [emit.console_login(who, t, ip, browser, mfa=False)]
    steps: list[tuple[Api, dict[str, Any] | None]] = [
        (("iam", "ListUsers", True), None),
        (("iam", "GetAccountSummary", True), None),
        (("iam", "CreateUser", False), {"userName": backdoor}),
        (
            ("iam", "AttachUserPolicy", False),
            {"userName": backdoor, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        ),
        (("iam", "CreateLoginProfile", False), {"userName": backdoor}),
        (("iam", "CreateAccessKey", False), {"userName": backdoor}),
    ]
    for api, params in steps:
        t += rng.uniform(15, 150)
        records.append(
            emit.record(
                who, t, api, "us-east-1", ip, console, mfa=False, console=True, params=params
            )
        )
    return records


def access_key_persistence(victim: Persona, ctx: DayContext, start: float) -> list[Record]:
    """Stolen role session mints long-term keys for an existing human user."""
    rng, emit, who = ctx.rng, ctx.emit, victim.principal
    _, ip = _attacker(rng, emit)
    ua = cat.user_agent(rng.choice(["aws-cli", "boto3"]), rng.randrange(10, 40))
    target = rng.choice(["admin-01", "admin-02", "dev-01", "dev-03"])
    t = start
    records = [emit.record(who, t, ("sts", "GetCallerIdentity", True), "us-east-1", ip, ua)]
    for api, params in (
        (("iam", "ListUsers", True), None),
        (("iam", "ListAccessKeys", True), {"userName": target}),
        (("iam", "CreateAccessKey", False), {"userName": target}),
    ):
        t += rng.uniform(5, 60)
        records.append(emit.record(who, t, api, "us-east-1", ip, ua, params=params))
    return records


def recon_burst(victim: Persona, ctx: DayContext, start: float) -> list[Record]:
    """Automated enumeration with a low-privilege key: many services, many denials."""
    rng, emit, who = ctx.rng, ctx.emit, victim.principal
    _, ip = _attacker(rng, emit)
    ua = _attacker_ua(rng, rng.randrange(10, 40))
    t = start
    records = []
    apis = list(cat.RECON_APIS)
    rng.shuffle(apis)
    for api in apis[: rng.randint(24, len(apis))]:
        for region in rng.sample(cat.REGIONS[:4], rng.randint(1, 2)):
            t += rng.uniform(0.2, 4)
            denied = api[0] in DENIABLE_SERVICES and rng.random() < 0.6
            records.append(
                emit.record(who, t, api, region, ip, ua, error="AccessDenied" if denied else None)
            )
    return records


def defense_evasion(victim: Persona, ctx: DayContext, start: float) -> list[Record]:
    """Admin credentials used to blind the account's audit and detection services."""
    rng, emit, who = ctx.rng, ctx.emit, victim.principal
    _, ip = _attacker(rng, emit)
    ua = cat.user_agent("aws-cli", rng.randrange(10, 40))
    t = start
    plan: list[tuple[Api, dict[str, Any] | None]] = [
        (("cloudtrail", "DescribeTrails", True), None),
        (("cloudtrail", "GetTrailStatus", True), {"name": "org-trail"}),
    ]
    if rng.random() < 0.35:  # stealthier: weaken instead of stop
        plan.append(
            (
                ("cloudtrail", "PutEventSelectors", False),
                {
                    "trailName": "org-trail",
                    "eventSelectors": [
                        {"readWriteType": "ReadOnly", "includeManagementEvents": True}
                    ],
                },
            )
        )
    else:
        plan.append((("cloudtrail", "StopLogging", False), {"name": "org-trail"}))
    plan.append((("guardduty", "ListDetectors", True), None))
    plan.append((("guardduty", "DeleteDetector", False), {"detectorId": DETECTOR_ID}))
    if rng.random() < 0.5:
        plan.append(
            (
                ("config", "StopConfigurationRecorder", False),
                {"configurationRecorderName": "default"},
            )
        )
    records = []
    for api, params in plan:
        t += rng.uniform(10, 90)
        records.append(emit.record(who, t, api, "us-east-1", ip, ua, params=params))
    return records


def low_and_slow(victim: Persona, ctx: DayContext, start: float) -> list[Record]:
    """Insider-style secret harvesting from the workload's own network and tooling.

    Deliberately close to the victim's normal behaviour; included to measure (and disclose)
    what behavioural baselines cannot see.
    """
    rng, emit, who = ctx.rng, ctx.emit, victim.principal
    if isinstance(victim, Automation):
        ip, ua = victim.ip(ctx), victim.ua(ctx)
    else:  # pragma: no cover - scenario only targets automation personas
        ip, ua = f"{cat.UNMAPPED_PREFIX}77", cat.user_agent("boto3", ctx.ua_version)
    t = start
    records = []
    for api in (
        ("secretsmanager", "ListSecrets", True),
        ("secretsmanager", "GetSecretValue", True),
        ("secretsmanager", "GetSecretValue", True),
        ("ssm", "GetParameters", True),
        ("kms", "Decrypt", True),
    ):
        t += rng.uniform(600, 7200)
        records.append(emit.record(who, t, api, "us-west-2", ip, ua))
    return records


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario(
            "stolen_access_key",
            "leaked IAM user key used from attacker hosting: recon, region sweep, compute abuse",
            frozenset({"cli_user"}),
            stolen_access_key,
        ),
        Scenario(
            "console_no_mfa_privesc",
            "phished console password without MFA, backdoor admin user created",
            frozenset({"no_mfa"}),
            console_no_mfa_privesc,
        ),
        Scenario(
            "access_key_persistence",
            "stolen automation-role session creates access keys for an existing user",
            frozenset({"ci"}),
            access_key_persistence,
        ),
        Scenario(
            "recon_burst",
            "automated enumeration of many services with many access denials",
            frozenset({"human"}),
            recon_burst,
        ),
        Scenario(
            "defense_evasion",
            "admin credentials used to stop/weaken CloudTrail, GuardDuty and Config",
            frozenset({"admin"}),
            defense_evasion,
        ),
        Scenario(
            "low_and_slow",
            "secret harvesting from the workload's own network and tooling over hours",
            frozenset({"workload"}),
            low_and_slow,
        ),
    )
}
