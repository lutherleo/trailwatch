"""Unusual IAM access-key creation (persistence via additional cloud credentials)."""

from __future__ import annotations

from collections import deque

from trailwatch.baseline import Dim
from trailwatch.config import Config
from trailwatch.model import Finding, Severity
from trailwatch.rules.base import EventContext, Rule
from trailwatch.window import BoundedLRU

HABIT_KEY_FOR_OTHER = "create-key-for-other"
HABIT_KEY_FOR_SELF = "create-key-for-self"
ONBOARDING_WINDOW = 3600.0


class AccessKeyCreationRule(Rule):
    rule_id = "unusual_access_key_creation"
    description = (
        "iam:CreateAccessKey by root (critical), for another user (high), or for oneself "
        "(medium). Downgraded two levels when the principal routinely does the same kind of "
        "key creation and one level when the caller created that user within the hour "
        "(onboarding); upgraded when made without MFA from an interactive session or from a "
        "network new to the principal. Failed attempts are one level lower."
    )
    techniques = ("T1098.001",)

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._created: BoundedLRU[str, deque[tuple[float, str]]] = BoundedLRU(
            config.state.max_rule_principals
        )

    def state_size(self) -> int:
        return len(self._created)

    def _created_recently(self, ctx: EventContext, user: str) -> bool:
        recent = self._created.peek(ctx.principal)
        return recent is not None and any(
            name == user and 0 <= ctx.now - when <= ONBOARDING_WINDOW for when, name in recent
        )

    def evaluate(self, ctx: EventContext) -> list[Finding]:
        event = ctx.event
        if not self.config.access_keys.enabled or event.source != "iam.amazonaws.com":
            return []
        if event.name == "CreateUser" and not event.failed:
            created = event.request_parameters.get("userName")
            if created:
                history = self._created.get_or_create(ctx.principal, lambda: deque(maxlen=16))
                history.append((ctx.now, str(created)))
            return []
        if event.name != "CreateAccessKey":
            return []
        identity = event.identity
        requested = event.request_parameters.get("userName")
        target = str(requested) if requested else (identity.user_name or "<self>")
        caller = identity.user_name if identity.type == "IAMUser" else None
        for_other = caller is None or target not in {caller, "<self>"}
        reasons: list[str] = []

        if identity.is_root:
            severity = Severity.CRITICAL
            reasons.append("caller is the account root user")
        else:
            habit = HABIT_KEY_FOR_OTHER if for_other else HABIT_KEY_FOR_SELF
            ctx.habits.append(habit)
            severity = Severity.HIGH if for_other else Severity.MEDIUM
            reasons.append(f"key for {'another principal' if for_other else 'own user'}")
            profile = ctx.profile
            routine = profile is not None and (
                profile.weight(Dim.HABIT, habit, ctx.now)
                >= self.config.access_keys.routine_min_weight
            )
            if routine:
                severity = severity.bump(-2)
                reasons.append("routine for this principal")
            elif for_other and self._created_recently(ctx, target):
                severity = severity.bump(-1)
                reasons.append("user was created by the same principal within the hour")
            if identity.mfa_authenticated is False and ctx.ua_family in {"console", "browser"}:
                severity = severity.bump(1)
                reasons.append("interactive session without MFA")
            if (
                ctx.warmed_up
                and profile is not None
                and ctx.asn is not None
                and profile.is_new(Dim.ASN, ctx.asn)
            ):
                severity = severity.bump(1)
                reasons.append(f"from network {ctx.asn} new to this principal")
        if event.failed:
            severity = severity.bump(-1)
            reasons.append(f"attempt failed ({event.error_code})")
        if severity == Severity.INFO:
            return []
        return [
            self.finding(
                ctx,
                severity,
                f"Access key created for {target}",
                "; ".join(reasons),
                dedup_key=target,
                attrs={"target_user": target, "for_other": for_other},
            )
        ]
