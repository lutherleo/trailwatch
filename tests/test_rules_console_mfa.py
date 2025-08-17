"""Rules-as-code tests: console sign-in without MFA followed by IAM changes."""

from __future__ import annotations

from conftest import CONSOLE_UA, T0, Harness, console_login, event, user_identity
from trailwatch.baseline import Dim
from trailwatch.model import Event, Finding, Severity
from trailwatch.parse import parse_record
from trailwatch.rules import ConsoleNoMfaRule
from trailwatch.rules.console_mfa import HABIT_NO_MFA_LOGIN, is_iam_change


def feed(h: Harness, rule: ConsoleNoMfaRule, ev: Event) -> list[Finding]:
    ctx = h.ctx(ev)
    findings = rule.evaluate(ctx)
    h.learn(ev, tuple(ctx.habits))
    return findings


def iam_change(name: str = "AttachUserPolicy", *, t: float, mfa: bool = False) -> Event:
    return event(
        name,
        "iam",
        t=t,
        ua=CONSOLE_UA,
        identity=user_identity("alice", mfa=mfa),
        params={"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        read_only=False,
    )


def test_no_mfa_login_then_iam_change_is_critical(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    login = console_login(t=T0)
    first = feed(harness, rule, login)
    assert [f.severity for f in first] == [Severity.LOW]
    findings = feed(harness, rule, iam_change(t=T0 + 600))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].evidence[0] == login.event_id
    assert findings[0].attrs["api"] == "iam:AttachUserPolicy"


def test_login_with_mfa_opens_no_window(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    assert feed(harness, rule, console_login(t=T0, mfa=True)) == []
    assert feed(harness, rule, iam_change(t=T0 + 60, mfa=True)) == []


def test_failed_login_opens_no_window(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    assert feed(harness, rule, console_login(t=T0, success=False)) == []
    assert feed(harness, rule, iam_change(t=T0 + 60)) == []


def test_change_after_window_is_ignored(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    feed(harness, rule, console_login(t=T0))
    assert feed(harness, rule, iam_change(t=T0 + 3 * 3600)) == []


def test_read_only_and_self_service_iam_calls_are_not_changes(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    feed(harness, rule, console_login(t=T0))
    assert feed(harness, rule, iam_change("ListUsers", t=T0 + 30)) == []
    assert feed(harness, rule, iam_change("ChangePassword", t=T0 + 40)) == []
    assert not is_iam_change(event("GetUser", "iam"))


def test_cli_call_with_mfa_session_is_not_linked(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    feed(harness, rule, console_login(t=T0))
    cli_change = event(
        "CreateUser", "iam", t=T0 + 60, identity=user_identity("alice", mfa=True), read_only=False
    )
    assert feed(harness, rule, cli_change) == []


def test_federated_sign_in_reporting_no_mfa_is_ignored(harness: Harness) -> None:
    rule = ConsoleNoMfaRule(harness.config)
    record = {
        "eventVersion": "1.08",
        "userIdentity": user_identity("AWSReservedSSO_Admin_abc", kind="AssumedRole"),
        "eventTime": "2026-03-02T09:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "eventID": "sso-login-1",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }
    assert feed(harness, rule, parse_record(record)) == []


def test_routine_no_mfa_login_is_silent_and_familiar_change_downgraded() -> None:
    h = Harness()
    rule = ConsoleNoMfaRule(h.config)
    for day in range(6, 0, -1):
        feed(h, rule, console_login(t=T0 - day * 86_400))
    h.learn(iam_change(t=T0 - 5 * 86_400), ())
    for day in range(4, 0, -1):
        h.learn(iam_change(t=T0 - day * 86_400))
    assert feed(h, rule, console_login(t=T0)) == []
    findings = feed(h, rule, iam_change(t=T0 + 120))
    assert [f.severity for f in findings] == [Severity.HIGH]
    profile = h.baseline.get(console_login().principal)
    assert profile is not None
    assert (
        profile.weight(Dim.HABIT, HABIT_NO_MFA_LOGIN, T0) >= h.config.baseline.familiar_min_weight
    )
