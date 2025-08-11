"""Core typed data model: parsed CloudTrail events, findings and alerts.

Everything downstream of the parser works on these immutable value objects rather than on raw
JSON dictionaries, so rules never have to defend against missing keys or wrong types.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class Severity(enum.IntEnum):
    """Ordered finding/alert severity. Higher is worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name (``"high"`` -> ``Severity.HIGH``)."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of {names}") from exc

    def bump(self, steps: int = 1) -> Severity:
        """Return the severity ``steps`` levels higher (or lower), clamped to the valid range."""
        return Severity(max(Severity.INFO, min(Severity.CRITICAL, int(self) + steps)))

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Identity:
    """The calling identity of a CloudTrail record (``userIdentity``), normalised.

    ``principal_key`` is the stable key used for baselining: an IAM user ARN, a role ARN (role
    sessions of the same role share a baseline, except SSO sessions which are per-person), the
    account root, or ``service:<name>`` for AWS service principals.
    """

    type: str
    principal_key: str
    arn: str
    account_id: str
    user_name: str | None = None
    access_key_id: str | None = None
    session_name: str | None = None
    mfa_authenticated: bool | None = None
    invoked_by: str | None = None

    @property
    def is_root(self) -> bool:
        return self.type == "Root"

    @property
    def is_service(self) -> bool:
        return self.type == "AWSService"


@dataclass(frozen=True, slots=True)
class Event:
    """One parsed CloudTrail management event."""

    event_id: str
    time: float
    name: str
    source: str
    region: str
    source_ip: str
    user_agent: str
    identity: Identity
    event_type: str = "AwsApiCall"
    error_code: str | None = None
    read_only: bool | None = None
    request_parameters: Mapping[str, Any] = field(default_factory=dict)
    response_elements: Mapping[str, Any] = field(default_factory=dict)
    additional_event_data: Mapping[str, Any] = field(default_factory=dict)
    recipient_account_id: str = ""

    @property
    def service(self) -> str:
        """Short service name: ``iam.amazonaws.com`` -> ``iam``."""
        return self.source.split(".", 1)[0]

    @property
    def api(self) -> str:
        """Service-qualified API name, e.g. ``iam:CreateUser``."""
        return f"{self.service}:{self.name}"

    @property
    def failed(self) -> bool:
        return self.error_code is not None

    @property
    def principal(self) -> str:
        return self.identity.principal_key

    @property
    def iso_time(self) -> str:
        return format_time(self.time)


def format_time(ts: float) -> str:
    """Format epoch seconds as a CloudTrail-style UTC timestamp (``2026-01-02T03:04:05Z``)."""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class Finding:
    """A single rule hit. Findings feed the risk scorer; severe ones also become alerts."""

    rule_id: str
    severity: Severity
    principal: str
    time: float
    title: str
    detail: str
    evidence: tuple[str, ...]
    dedup_key: str = ""
    techniques: tuple[str, ...] = ()
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceRef:
    """A pointer to an event that supports an alert, with enough context to triage it."""

    event_id: str
    time: float
    api: str
    source_ip: str
    region: str


@dataclass(slots=True)
class Alert:
    """An emitted alert. Mutable only so the deduplicator can fold repeats into it."""

    alert_id: str
    kind: str  # "rule" (a single severe finding) or "risk" (decayed score crossed threshold)
    rule_id: str
    severity: Severity
    principal: str
    account_id: str
    created: float
    title: str
    summary: str
    risk_score: float
    techniques: list[str]
    findings: list[Finding]
    evidence: list[EvidenceRef]
    last_seen: float = 0.0
    count: int = 1

    def __post_init__(self) -> None:
        if not self.last_seen:
            self.last_seen = self.created

    def evidence_ids(self) -> set[str]:
        ids = {ref.event_id for ref in self.evidence}
        for finding in self.findings:
            ids.update(finding.evidence)
        return ids
