"""Console sign-in without MFA, followed by IAM changes in the same session window."""

from __future__ import annotations

from dataclasses import dataclass

from trailwatch.baseline import Dim
from trailwatch.config import Config
from trailwatch.model import Event, Finding
from trailwatch.parse import console_login_succeeded, console_login_used_mfa, is_console_login
from trailwatch.rules.base import EventContext, Rule
from trailwatch.useragent import INTERACTIVE_FAMILIES
from trailwatch.window import BoundedLRU

HABIT_NO_MFA_LOGIN = "console-login-no-mfa"
# Only IAM users and root sign in with an AWS-managed password; federated (SSO/SAML) sign-ins
# always report MFAUsed=No because MFA happens at the identity provider, invisible to CloudTrail.
FEDERATION_BLIND_TYPES = frozenset({"IAMUser", "Root"})
READ_PREFIXES = ("Get", "List", "Generate", "Simulate")
# Self-service IAM calls a user makes on their own credentials; not privilege changes.
SELF_SERVICE = frozenset(
    {"ChangePassword", "EnableMFADevice", "CreateVirtualMFADevice", "ResyncMFADevice"}
)


def is_iam_change(event: Event) -> bool:
    return (
        event.source == "iam.amazonaws.com"
        and event.error_code is None
        and not event.name.startswith(READ_PREFIXES)
        and event.name not in SELF_SERVICE
    )


@dataclass(frozen=True, slots=True)
class _Login:
    time: float
    event_id: str
    source_ip: str


class ConsoleNoMfaRule(Rule):
    rule_id = "console_no_mfa_iam_change"
    description = (
        "A successful console sign-in without MFA opens a window (console_mfa.window_minutes); "
        "any IAM write by the same principal from an interactive session inside the window is "
        "critical. The sign-in alone is low severity (info when it is the principal's habit)."
    )
    techniques = ("T1078.004", "T1098")

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._logins: BoundedLRU[str, _Login] = BoundedLRU(config.state.max_rule_principals)

    def state_size(self) -> int:
        return len(self._logins)

    def evaluate(self, ctx: EventContext) -> list[Finding]:
        cfg = self.config.console_mfa
        event = ctx.event
        if not cfg.enabled:
            return []
        if is_console_login(event):
            return self._on_login(ctx)
        if not is_iam_change(event):
            return []
        login = self._logins.peek(ctx.principal)
        if login is None or not 0 <= ctx.now - login.time <= cfg.window_minutes * 60:
            return []
        interactive = ctx.ua_family in INTERACTIVE_FAMILIES
        if not interactive and event.identity.mfa_authenticated is not False:
            return []
        severity = cfg.change_severity
        profile = ctx.profile
        if (
            self.config.baseline.suppress_familiar
            and profile is not None
            and ctx.familiar(profile.weight(Dim.HABIT, HABIT_NO_MFA_LOGIN, ctx.now))
            and ctx.familiar(profile.weight(Dim.API, event.api, ctx.now))
        ):
            severity = severity.bump(-1)
        minutes = (ctx.now - login.time) / 60
        return [
            self.finding(
                ctx,
                severity,
                f"IAM change ({event.name}) after console sign-in without MFA",
                f"{event.api} {minutes:.0f} min after a no-MFA console sign-in from "
                f"{login.source_ip}",
                evidence=(login.event_id, event.event_id),
                dedup_key=login.event_id,
                attrs={"api": event.api, "minutes_after_login": round(minutes, 1)},
            )
        ]

    def _on_login(self, ctx: EventContext) -> list[Finding]:
        event = ctx.event
        if (
            event.identity.type not in FEDERATION_BLIND_TYPES
            or not console_login_succeeded(event)
            or console_login_used_mfa(event) is not False
        ):
            return []
        self._logins.put(ctx.principal, _Login(ctx.now, event.event_id, event.source_ip))
        ctx.habits.append(HABIT_NO_MFA_LOGIN)
        profile = ctx.profile
        routine = profile is not None and ctx.familiar(
            profile.weight(Dim.HABIT, HABIT_NO_MFA_LOGIN, ctx.now)
        )
        if routine:
            return []
        return [
            self.finding(
                ctx,
                self.config.console_mfa.login_severity,
                "Console sign-in without MFA",
                f"ConsoleLogin succeeded without MFA from {event.source_ip} ({ctx.location})",
                dedup_key=event.event_id,
                techniques=("T1078.004",),
            )
        ]
