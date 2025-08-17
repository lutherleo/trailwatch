"""Shared test helpers: raw CloudTrail record factories and rule-context builders."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime
from typing import Any

import pytest

from trailwatch.baseline import BaselineStore, Observation
from trailwatch.config import Config
from trailwatch.model import Event
from trailwatch.netmap import NetMap
from trailwatch.parse import parse_record
from trailwatch.rules.base import EventContext
from trailwatch.useragent import classify

ACCOUNT = "111122223333"
T0 = datetime(2026, 3, 2, 9, 0, tzinfo=UTC).timestamp()  # a Monday
HQ_IP = "100.64.1.10"  # Seattle, corporate (AS64512)
HOME_IP = "100.68.3.4"  # Seattle, ISP (AS64520)
DUBLIN_IP = "100.65.0.9"  # Dublin office (AS64513)
VPN_FRA_IP = "100.66.0.5"  # Frankfurt corporate VPN (AS64514)
MOBILE_LA_IP = "100.72.9.9"  # Los Angeles mobile (AS64524)
HOSTILE_AMS_IP = "198.18.33.7"  # Amsterdam hosting (AS64550)
DALLAS_HOSTING_IP = "198.18.65.1"  # Dallas hosting (AS64552)
CLI_UA = "aws-cli/2.15.30 Python/3.11.8 Darwin/23.4.0 exe/x86_64 prompt/off"
BOTO_UA = "Boto3/1.34.69 md/Botocore#1.34.69 Botocore/1.34.69"
CONSOLE_UA = "console.amazonaws.com"
BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"

_ids = itertools.count(1)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def user_identity(
    user: str = "alice", *, mfa: bool | None = None, kind: str = "IAMUser"
) -> dict[str, Any]:
    if kind == "IAMUser":
        ident: dict[str, Any] = {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
            "accountId": ACCOUNT,
            "userName": user,
            "accessKeyId": "AKIAEXAMPLE",
        }
    elif kind == "AssumedRole":
        ident = {
            "type": "AssumedRole",
            "principalId": f"AROAEXAMPLE:{user}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{user}/session-1",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAEXAMPLE",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/{user}",
                    "userName": user,
                }
            },
        }
    elif kind == "Root":
        ident = {"type": "Root", "principalId": ACCOUNT, "accountId": ACCOUNT}
    else:
        raise ValueError(kind)
    if mfa is not None:
        ident.setdefault("sessionContext", {})["attributes"] = {
            "mfaAuthenticated": "true" if mfa else "false"
        }
    return ident


def raw(
    name: str = "DescribeInstances",
    source: str = "ec2",
    *,
    t: float = T0,
    ip: str = HQ_IP,
    ua: str = CLI_UA,
    region: str = "us-east-1",
    identity: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    error: str | None = None,
    read_only: bool | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": identity if identity is not None else user_identity(),
        "eventTime": iso(t),
        "eventSource": f"{source}.amazonaws.com",
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": params,
        "responseElements": response,
        "eventID": f"evt-{next(_ids):06d}",
        "readOnly": read_only
        if read_only is not None
        else name.startswith(("Describe", "List", "Get")),
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    if error:
        record["errorCode"] = error
    if extra:
        record.update(extra)
    return record


def event(name: str = "DescribeInstances", source: str = "ec2", **kwargs: Any) -> Event:
    return parse_record(raw(name, source, **kwargs))


def console_login(
    user: str = "alice", *, t: float = T0, ip: str = HQ_IP, mfa: bool = False, success: bool = True
) -> Event:
    identity = user_identity(user)
    identity.pop("accessKeyId")
    record = raw(
        "ConsoleLogin",
        "signin",
        t=t,
        ip=ip,
        ua=BROWSER_UA,
        identity=identity,
        response={"ConsoleLogin": "Success" if success else "Failure"},
        extra={
            "eventType": "AwsConsoleSignIn",
            "additionalEventData": {"MFAUsed": "Yes" if mfa else "No"},
        },
        read_only=False,
    )
    return parse_record(record)


class Harness:
    """Builds :class:`EventContext` objects the way the engine does, for rule unit tests."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.netmap = NetMap.bundled()
        self.baseline = BaselineStore(self.config.baseline)

    def ctx(self, ev: Event) -> EventContext:
        profile = self.baseline.get(ev.principal)
        return EventContext(
            event=ev,
            net=self.netmap.lookup(ev.source_ip),
            ua_family=classify(ev.user_agent),
            profile=profile,
            baseline=self.baseline,
            config=self.config,
            warmed_up=profile is not None and profile.warmed_up(ev.time, self.config.baseline),
        )

    def learn(self, ev: Event, habits: tuple[str, ...] = ()) -> None:
        net = self.netmap.lookup(ev.source_ip)
        self.baseline.observe(
            ev.principal,
            Observation(
                time=ev.time,
                api=ev.api,
                region=ev.region,
                ua_family=classify(ev.user_agent),
                asn=net.asn_label if net else None,
                country=net.country if net else None,
                habits=habits,
            ),
        )

    def warm(
        self,
        user: str = "alice",
        *,
        days: int = 10,
        ip: str = HQ_IP,
        ua: str = CLI_UA,
        per_day: int = 8,
        apis: tuple[tuple[str, str], ...] = (("DescribeInstances", "ec2"), ("ListBuckets", "s3")),
        identity_kind: str = "IAMUser",
        habits: tuple[str, ...] = (),
        end: float = T0,
    ) -> None:
        """Teach the baseline ``days`` days of routine activity ending just before ``end``."""
        for day in range(days, 0, -1):
            for i in range(per_day):
                name, source = apis[i % len(apis)]
                ev = event(
                    name,
                    source,
                    t=end - day * 86_400 + i * 60,
                    ip=ip,
                    ua=ua,
                    identity=user_identity(user, kind=identity_kind),
                )
                self.learn(ev, habits)


@pytest.fixture
def harness() -> Harness:
    return Harness()
