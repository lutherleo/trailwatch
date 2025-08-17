"""Rules-as-code tests: unusual access-key creation."""

from __future__ import annotations

from conftest import CONSOLE_UA, HOSTILE_AMS_IP, T0, Harness, event, user_identity
from trailwatch.baseline import Dim
from trailwatch.config import Config
from trailwatch.model import Event, Finding, Severity
from trailwatch.rules import AccessKeyCreationRule
from trailwatch.rules.access_keys import HABIT_KEY_FOR_OTHER


def create_key(
    target: str | None,
    *,
    caller: str = "alice",
    kind: str = "IAMUser",
    t: float = T0,
    ip: str = "100.64.1.10",
    ua: str = "aws-cli/2.15.30",
    mfa: bool | None = None,
    error: str | None = None,
) -> Event:
    return event(
        "CreateAccessKey",
        "iam",
        t=t,
        ip=ip,
        ua=ua,
        identity=user_identity(caller, kind=kind, mfa=mfa),
        params={"userName": target} if target else None,
        error=error,
        read_only=False,
    )


def feed(h: Harness, rule: AccessKeyCreationRule, ev: Event) -> list[Finding]:
    ctx = h.ctx(ev)
    findings = rule.evaluate(ctx)
    h.learn(ev, tuple(ctx.habits))
    return findings


def test_key_for_another_user_is_high(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    findings = feed(harness, rule, create_key("bob"))
    assert [f.severity for f in findings] == [Severity.HIGH]
    assert findings[0].attrs == {"target_user": "bob", "for_other": True}


def test_key_for_self_is_medium(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    assert [f.severity for f in feed(harness, rule, create_key(None))] == [Severity.MEDIUM]
    assert [f.severity for f in feed(harness, rule, create_key("alice"))] == [Severity.MEDIUM]


def test_root_key_creation_is_critical(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    findings = feed(harness, rule, create_key(None, kind="Root"))
    assert [f.severity for f in findings] == [Severity.CRITICAL]


def test_role_creating_key_for_user_counts_as_other(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    findings = feed(
        harness, rule, create_key("admin-01", caller="terraform-ci", kind="AssumedRole")
    )
    assert [f.severity for f in findings] == [Severity.HIGH]


def test_routine_key_creation_is_downgraded_two_levels(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    for day in (9, 6, 3):
        feed(harness, rule, create_key(f"hire-{day}", t=T0 - day * 86_400))
    profile = harness.baseline.get(create_key("x").principal)
    assert profile is not None
    assert profile.weight(Dim.HABIT, HABIT_KEY_FOR_OTHER, T0) >= 1.5
    findings = feed(harness, rule, create_key("hire-new"))
    assert [f.severity for f in findings] == [Severity.LOW]
    assert "routine" in findings[0].detail


def test_onboarding_pattern_downgrades_one_level(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    created = event("CreateUser", "iam", t=T0, params={"userName": "carol"}, read_only=False)
    assert feed(harness, rule, created) == []
    findings = feed(harness, rule, create_key("carol", t=T0 + 120))
    assert [f.severity for f in findings] == [Severity.MEDIUM]
    later = feed(harness, rule, create_key("dave", t=T0 + 200))
    assert [f.severity for f in later] == [Severity.HIGH]


def test_interactive_no_mfa_and_new_network_escalate() -> None:
    h = Harness()
    h.warm()
    rule = AccessKeyCreationRule(h.config)
    findings = feed(
        h, rule, create_key("bob", ip=HOSTILE_AMS_IP, ua=CONSOLE_UA, mfa=False, t=T0 + 10)
    )
    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert "without MFA" in findings[0].detail
    assert "new to this principal" in findings[0].detail


def test_failed_attempt_is_one_level_lower(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    findings = feed(harness, rule, create_key("bob", error="AccessDenied"))
    assert [f.severity for f in findings] == [Severity.MEDIUM]
    assert "attempt failed" in findings[0].detail


def test_routine_self_key_drops_to_info_and_is_not_reported(harness: Harness) -> None:
    rule = AccessKeyCreationRule(harness.config)
    for day in (8, 4):
        feed(harness, rule, create_key(None, t=T0 - day * 86_400))
    assert feed(harness, rule, create_key(None)) == []


def test_other_iam_calls_and_disabled_rule_are_ignored() -> None:
    h = Harness(Config().with_overrides({"access_keys.enabled": False}))
    rule = AccessKeyCreationRule(h.config)
    assert feed(h, rule, create_key("bob")) == []
    enabled = AccessKeyCreationRule(Config())
    assert enabled.evaluate(Harness().ctx(event("ListAccessKeys", "iam"))) == []
    assert enabled.state_size() == 0
