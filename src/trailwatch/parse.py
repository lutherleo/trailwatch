"""Parse raw CloudTrail records (dicts decoded from JSON) into typed :class:`Event` objects.

The parser is deliberately strict about the handful of fields detection depends on
(``eventTime``, ``eventName``, ``eventSource``, ``userIdentity``) and lenient about everything
else, because real trails contain many record shapes (service events, failed sign-ins for
non-existent users, cross-account calls, ...).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from trailwatch.model import Event, Identity

SSO_ROLE_PREFIX = "AWSReservedSSO_"


class ParseError(ValueError):
    """A record could not be turned into an :class:`Event`."""


def _str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes"}:
            return True
        if lowered in {"false", "no"}:
            return False
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def parse_time(value: Any) -> float:
    """Parse a CloudTrail ``eventTime`` (ISO-8601, UTC ``Z`` suffix) into epoch seconds."""
    if not isinstance(value, str) or not value:
        raise ParseError(f"eventTime missing or not a string: {value!r}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ParseError(f"invalid eventTime {value!r}") from exc
    if parsed.tzinfo is None:
        raise ParseError(f"eventTime {value!r} has no timezone")
    return parsed.timestamp()


def parse_identity(raw: Any, fallback_account: str = "") -> Identity:
    """Normalise a ``userIdentity`` block and derive its baseline ``principal_key``."""
    if not isinstance(raw, Mapping):
        raise ParseError("userIdentity missing or not an object")
    id_type = _str(raw.get("type")) or "Unknown"
    account = _str(raw.get("accountId")) or fallback_account
    arn = _str(raw.get("arn")) or ""
    user_name = _str(raw.get("userName"))
    session_ctx = _mapping(raw.get("sessionContext"))
    attributes = _mapping(session_ctx.get("attributes"))
    issuer = _mapping(session_ctx.get("sessionIssuer"))
    mfa = _bool(attributes.get("mfaAuthenticated"))
    invoked_by = _str(raw.get("invokedBy"))
    session_name: str | None = None

    if id_type == "Root":
        key = f"arn:aws:iam::{account}:root"
        arn = arn or key
    elif id_type == "IAMUser":
        if not arn and user_name:
            arn = f"arn:aws:iam::{account}:user/{user_name}"
        key = arn or f"iam-user:{account}:{_str(raw.get('principalId')) or 'unknown'}"
    elif id_type == "AssumedRole":
        role_arn = _str(issuer.get("arn")) or ""
        role_name = _str(issuer.get("userName")) or ""
        session_name = arn.rsplit("/", 1)[-1] if arn.count("/") >= 2 else None
        if not role_arn and arn:
            # arn:aws:sts::acct:assumed-role/Role/session -> arn:aws:iam::acct:role/Role
            parts = arn.split(":", 5)
            if len(parts) == 6 and parts[5].startswith("assumed-role/"):
                role_name = parts[5].split("/")[1]
                role_arn = f"arn:aws:iam::{parts[4]}:role/{role_name}"
        if role_name.startswith(SSO_ROLE_PREFIX) and session_name:
            key = f"{role_arn}/{session_name}"
        else:
            key = role_arn or arn or "assumed-role:unknown"
        user_name = user_name or role_name or None
    elif id_type == "AWSService":
        key = f"service:{invoked_by or 'unknown'}"
    else:
        key = arn or f"{id_type.lower()}:{account}:{_str(raw.get('principalId')) or 'unknown'}"

    return Identity(
        type=id_type,
        principal_key=key,
        arn=arn,
        account_id=account,
        user_name=user_name,
        access_key_id=_str(raw.get("accessKeyId")),
        session_name=session_name,
        mfa_authenticated=mfa,
        invoked_by=invoked_by,
    )


def parse_record(raw: Any) -> Event:
    """Convert one decoded CloudTrail record into an :class:`Event`.

    Raises :class:`ParseError` when a field that detection depends on is missing or malformed.
    """
    if not isinstance(raw, Mapping):
        raise ParseError(f"record is not an object: {type(raw).__name__}")
    name = _str(raw.get("eventName"))
    source = _str(raw.get("eventSource"))
    if not name or not source:
        raise ParseError("eventName/eventSource missing")
    recipient = _str(raw.get("recipientAccountId")) or ""
    identity = parse_identity(raw.get("userIdentity"), fallback_account=recipient)
    event_id = _str(raw.get("eventID"))
    if not event_id:
        raise ParseError("eventID missing")
    return Event(
        event_id=event_id,
        time=parse_time(raw.get("eventTime")),
        name=name,
        source=source,
        region=_str(raw.get("awsRegion")) or "unknown",
        source_ip=_str(raw.get("sourceIPAddress")) or "",
        user_agent=_str(raw.get("userAgent")) or "",
        identity=identity,
        event_type=_str(raw.get("eventType")) or "AwsApiCall",
        error_code=_str(raw.get("errorCode")),
        read_only=_bool(raw.get("readOnly")),
        request_parameters=_mapping(raw.get("requestParameters")),
        response_elements=_mapping(raw.get("responseElements")),
        additional_event_data=_mapping(raw.get("additionalEventData")),
        recipient_account_id=recipient or identity.account_id,
    )


def is_console_login(event: Event) -> bool:
    return event.name == "ConsoleLogin" and event.source == "signin.amazonaws.com"


def console_login_succeeded(event: Event) -> bool:
    outcome = _str(event.response_elements.get("ConsoleLogin"))
    return outcome == "Success" and event.error_code is None


def console_login_used_mfa(event: Event) -> bool | None:
    """``MFAUsed`` from a ConsoleLogin record (``None`` when absent, e.g. SSO federation)."""
    return _bool(event.additional_event_data.get("MFAUsed"))
