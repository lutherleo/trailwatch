"""Builders for CloudTrail-shaped records (the JSON the real service writes).

Records follow the CloudTrail record schema (``eventVersion`` 1.08) closely enough that the
parser cannot tell them apart from real management events; identifiers (event IDs, access key
IDs, principal IDs) are derived from the simulator's seeded RNG so every run is reproducible.
"""

from __future__ import annotations

import ipaddress
import random
import uuid
from dataclasses import dataclass, field
from typing import Any

from trailwatch.model import format_time
from trailwatch.netmap import NetMap

ACCOUNT_ID = "111122223333"
SSO_ROLE = "AWSReservedSSO_DeveloperAccess_5f2c9a1b7d3e4f60"
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _token(rng: random.Random, prefix: str, length: int = 16) -> str:
    return prefix + "".join(rng.choice(_ALNUM) for _ in range(length))


@dataclass(frozen=True, slots=True)
class Principal:
    """A simulated identity. ``kind`` is ``user`` (IAM user), ``role``, ``sso`` or ``root``."""

    kind: str
    name: str
    principal_id: str
    key_id: str
    session: str = ""

    @property
    def arn(self) -> str:
        if self.kind == "user":
            return f"arn:aws:iam::{ACCOUNT_ID}:user/{self.name}"
        if self.kind == "root":
            return f"arn:aws:iam::{ACCOUNT_ID}:root"
        role = SSO_ROLE if self.kind == "sso" else self.name
        return f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role}/{self.session or self.name}"

    @property
    def label(self) -> str:
        """The principal key trailwatch derives for this identity (used in labels/metadata)."""
        if self.kind == "user":
            return self.arn
        if self.kind == "root":
            return self.arn
        if self.kind == "sso":
            return f"arn:aws:iam::{ACCOUNT_ID}:role/{SSO_ROLE}/{self.session}"
        return f"arn:aws:iam::{ACCOUNT_ID}:role/{self.name}"


def make_principal(rng: random.Random, kind: str, name: str, session: str = "") -> Principal:
    prefix = {"user": "AIDA", "role": "AROA", "sso": "AROA", "root": ""}[kind]
    principal_id = ACCOUNT_ID if kind == "root" else _token(rng, prefix)
    return Principal(kind, name, principal_id, _token(rng, "AKIA"), session)


@dataclass(slots=True)
class Emitter:
    """Creates records with deterministic identifiers and realistic addresses."""

    rng: random.Random
    netmap: NetMap
    _networks: dict[int, list[ipaddress.IPv4Network]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for info in self.netmap.networks:
            net = ipaddress.ip_network(info.cidr)
            if isinstance(net, ipaddress.IPv4Network):
                self._networks.setdefault(info.asn, []).append(net)

    def ip_in(self, asn: int) -> str:
        """A random host address inside one of ``asn``'s networks."""
        nets = self._networks[asn]
        net = nets[self.rng.randrange(len(nets))]
        return str(net.network_address + self.rng.randrange(1, net.num_addresses - 1))

    def stable_ip(self, asn: int, slot: int) -> str:
        """A deterministic address in ``asn`` (e.g. one home router or one office NAT)."""
        net = self._networks[asn][0]
        return str(net.network_address + 1 + (slot * 7919) % (net.num_addresses - 2))

    def identity(
        self, who: Principal, mfa: bool | None, console: bool, when: float
    ) -> dict[str, Any]:
        if who.kind == "root":
            ident: dict[str, Any] = {
                "type": "Root",
                "principalId": who.principal_id,
                "arn": who.arn,
                "accountId": ACCOUNT_ID,
            }
        elif who.kind == "user":
            ident = {
                "type": "IAMUser",
                "principalId": who.principal_id,
                "arn": who.arn,
                "accountId": ACCOUNT_ID,
                "userName": who.name,
            }
        else:
            role = SSO_ROLE if who.kind == "sso" else who.name
            ident = {
                "type": "AssumedRole",
                "principalId": f"{who.principal_id}:{who.session or who.name}",
                "arn": who.arn,
                "accountId": ACCOUNT_ID,
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": who.principal_id,
                        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{role}",
                        "accountId": ACCOUNT_ID,
                        "userName": role,
                    }
                },
            }
        if console or who.kind in {"role", "sso"}:
            ident["accessKeyId"] = "ASIA" + who.key_id[4:]
            ctx = ident.setdefault("sessionContext", {})
            ctx["attributes"] = {
                "creationDate": format_time(when - 600),
                "mfaAuthenticated": "true" if mfa else "false",
            }
        elif who.kind == "user":
            ident["accessKeyId"] = who.key_id
        return ident

    def record(
        self,
        who: Principal,
        when: float,
        api: tuple[str, str, bool],
        region: str,
        ip: str,
        user_agent: str,
        *,
        mfa: bool | None = None,
        console: bool = False,
        params: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        service, name, read_only = api
        record: dict[str, Any] = {
            "eventVersion": "1.08",
            "userIdentity": self.identity(who, mfa, console, when),
            "eventTime": format_time(when),
            "eventSource": f"{service}.amazonaws.com",
            "eventName": name,
            "awsRegion": "us-east-1" if service in {"iam", "sts", "organizations"} else region,
            "sourceIPAddress": ip,
            "userAgent": user_agent,
            "requestParameters": params,
            "responseElements": response,
            "requestID": str(uuid.UUID(int=self.rng.getrandbits(128), version=4)),
            "eventID": str(uuid.UUID(int=self.rng.getrandbits(128), version=4)),
            "readOnly": read_only,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": ACCOUNT_ID,
            "eventCategory": "Management",
        }
        if error is not None:
            record["errorCode"] = error
            record["errorMessage"] = (
                f"User: {who.arn} is not authorized to perform: {service}:{name}"
            )
            record["responseElements"] = None
        return record

    def console_login(
        self, who: Principal, when: float, ip: str, user_agent: str, mfa: bool
    ) -> dict[str, Any]:
        record = self.record(
            who,
            when,
            ("signin", "ConsoleLogin", False),
            "us-east-1",
            ip,
            user_agent,
            response={"ConsoleLogin": "Success"},
        )
        identity = record["userIdentity"]
        identity.pop("accessKeyId", None)
        if who.kind in {"user", "root"}:
            identity.pop("sessionContext", None)
        record["eventType"] = "AwsConsoleSignIn"
        record["additionalEventData"] = {
            "LoginTo": "https://console.aws.amazon.com/console/home",
            "MobileVersion": "No",
            # Federated (SSO) sign-ins report MFAUsed=No: MFA happened at the identity provider.
            "MFAUsed": "Yes" if mfa and who.kind != "sso" else "No",
        }
        return record
