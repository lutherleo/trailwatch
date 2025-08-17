"""Rules-as-code tests: enumeration bursts."""

from __future__ import annotations

from conftest import BOTO_UA, HOSTILE_AMS_IP, T0, Harness, event, user_identity
from trailwatch.config import Config
from trailwatch.model import Event, Finding, Severity
from trailwatch.rules import EnumerationBurstRule
from trailwatch.rules.enumeration import is_recon

SERVICES = ("ec2", "iam", "s3", "rds", "lambda", "kms", "sns", "sqs")


def recon_calls(n: int, start: float, *, user: str = "alice", denied: bool = False) -> list[Event]:
    calls = []
    for i in range(n):
        service = SERVICES[i % len(SERVICES)]
        calls.append(
            event(
                f"List{service.title()}Thing{i}",
                service,
                t=start + i * 3,
                ip=HOSTILE_AMS_IP,
                ua=BOTO_UA,
                identity=user_identity(user),
                error="AccessDenied" if denied else None,
            )
        )
    return calls


def feed_all(h: Harness, rule: EnumerationBurstRule, events: list[Event]) -> list[Finding]:
    out: list[Finding] = []
    for ev in events:
        out.extend(rule.evaluate(h.ctx(ev)))
        h.learn(ev)
    return out


def test_volume_burst_fires_once_per_window() -> None:
    h = Harness()
    h.warm()
    rule = EnumerationBurstRule(h.config)
    findings = feed_all(h, rule, recon_calls(40, T0))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].attrs["distinct_apis"] == 20
    assert findings[0].attrs["services"] >= 4
    assert len(findings[0].evidence) <= 20


def test_denial_storm_alone_is_medium_for_warm_principal() -> None:
    h = Harness()
    h.warm()
    rule = EnumerationBurstRule(h.config)
    calls = [
        event("CreateUser", "iam", t=T0 + i, error="AccessDenied", read_only=False)
        for i in range(12)
    ]
    findings = feed_all(h, rule, calls)
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_volume_and_denials_together_are_high() -> None:
    h = Harness()
    rule = EnumerationBurstRule(h.config)
    findings = feed_all(h, rule, recon_calls(30, T0, denied=True))
    # The denial storm fires first (low: cold principal), then escalates once volume appears.
    assert [f.severity for f in findings] == [Severity.LOW, Severity.HIGH]


def test_slow_enumeration_spread_beyond_window_does_not_fire(harness: Harness) -> None:
    rule = EnumerationBurstRule(harness.config)
    calls = [
        event(f"DescribeThing{i}", SERVICES[i % 8], t=T0 + i * 120, identity=user_identity())
        for i in range(30)
    ]
    assert feed_all(harness, rule, calls) == []


def test_principal_with_scanning_history_is_suppressed() -> None:
    h = Harness()
    h.warm(user="scanner", identity_kind="AssumedRole")
    rule = EnumerationBurstRule(h.config)
    for day in (3, 2, 1):
        feed_all(h, rule, recon_calls(30, T0 - day * 86_400, user="scanner"))
    assert feed_all(h, rule, recon_calls(30, T0, user="scanner")) == []
    # ...but a much larger burst than ever before still fires.
    bigger = feed_all(h, rule, recon_calls(120, T0 + 3600, user="scanner"))
    assert bigger


def test_unwarmed_volume_burst_is_medium(harness: Harness) -> None:
    rule = EnumerationBurstRule(harness.config)
    findings = feed_all(harness, rule, recon_calls(25, T0))
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_non_recon_calls_are_ignored_and_rule_can_be_disabled() -> None:
    h = Harness(Config().with_overrides({"enumeration.enabled": False}))
    assert feed_all(h, EnumerationBurstRule(h.config), recon_calls(40, T0)) == []
    write = event("RunInstances", "ec2", read_only=False)
    assert not is_recon(write)
    rule = EnumerationBurstRule(Config())
    assert rule.evaluate(Harness().ctx(write)) == []
    assert rule.state_size() == 0
