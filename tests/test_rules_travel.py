"""Rules-as-code tests: impossible travel."""

from __future__ import annotations

from conftest import (
    DUBLIN_IP,
    HOME_IP,
    HOSTILE_AMS_IP,
    HQ_IP,
    MOBILE_LA_IP,
    T0,
    VPN_FRA_IP,
    Harness,
    event,
    user_identity,
)
from trailwatch.config import Config
from trailwatch.model import Finding, Severity
from trailwatch.rules import ImpossibleTravelRule


def run(h: Harness, rule: ImpossibleTravelRule, ip: str, t: float) -> list[Finding]:
    ev = event(t=t, ip=ip)
    findings = rule.evaluate(h.ctx(ev))
    h.learn(ev)
    return findings


def test_seattle_to_amsterdam_in_ten_minutes_is_high(harness: Harness) -> None:
    harness.warm()
    rule = ImpossibleTravelRule(harness.config)
    assert run(harness, rule, HQ_IP, T0) == []
    findings = rule.evaluate(harness.ctx(event(t=T0 + 600, ip=HOSTILE_AMS_IP)))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.attrs["distance_km"] > 7000
    assert "Seattle, US -> Amsterdam, NL" in finding.title
    assert len(finding.evidence) == 2


def test_plausible_flight_is_not_flagged(harness: Harness) -> None:
    rule = ImpossibleTravelRule(harness.config)
    run(harness, rule, HQ_IP, T0)
    # ~7,800 km in 12 hours = 650 km/h: an airliner.
    assert run(harness, rule, HOSTILE_AMS_IP, T0 + 12 * 3600) == []


def test_same_metro_networks_are_below_min_distance(harness: Harness) -> None:
    rule = ImpossibleTravelRule(harness.config)
    run(harness, rule, HQ_IP, T0)
    assert run(harness, rule, HOME_IP, T0 + 60) == []


def test_familiar_vpn_pair_is_suppressed() -> None:
    h = Harness()
    rule = ImpossibleTravelRule(h.config)
    for day in range(10):
        for ip in (HQ_IP, VPN_FRA_IP):
            h.learn(event(t=T0 - (10 - day) * 86_400, ip=ip))
            h.learn(event(t=T0 - (10 - day) * 86_400 + 60, ip=ip))
    run(h, rule, HQ_IP, T0)
    assert run(h, rule, VPN_FRA_IP, T0 + 300) == []


def test_familiarity_suppression_can_be_disabled() -> None:
    config = Config().with_overrides({"baseline.suppress_familiar": False})
    h = Harness(config)
    rule = ImpossibleTravelRule(config)
    for day in range(10):
        for ip in (HQ_IP, VPN_FRA_IP):
            h.learn(event(t=T0 - (10 - day) * 86_400, ip=ip))
    run(h, rule, HQ_IP, T0)
    assert len(run(h, rule, VPN_FRA_IP, T0 + 300)) == 1


def test_vpn_or_mobile_networks_downgrade_severity(harness: Harness) -> None:
    harness.warm()
    rule = ImpossibleTravelRule(harness.config)
    run(harness, rule, DUBLIN_IP, T0)
    findings = run(harness, rule, MOBILE_LA_IP, T0 + 600)
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_unwarmed_principal_is_downgraded(harness: Harness) -> None:
    rule = ImpossibleTravelRule(harness.config)
    run(harness, rule, HQ_IP, T0)
    findings = run(harness, rule, HOSTILE_AMS_IP, T0 + 600)
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_late_event_does_not_rewind_position(harness: Harness) -> None:
    rule = ImpossibleTravelRule(harness.config)
    run(harness, rule, HQ_IP, T0)
    assert run(harness, rule, HOSTILE_AMS_IP, T0 - 600) == []
    assert run(harness, rule, HQ_IP, T0 + 60) == []


def test_unknown_networks_are_ignored(harness: Harness) -> None:
    rule = ImpossibleTravelRule(harness.config)
    run(harness, rule, HQ_IP, T0)
    assert run(harness, rule, "192.0.2.10", T0 + 60) == []
    assert run(harness, rule, "ec2.amazonaws.com", T0 + 61) == []


def test_state_is_bounded_by_config() -> None:
    config = Config().with_overrides({"state.max_rule_principals": 5})
    h = Harness(config)
    rule = ImpossibleTravelRule(config)
    for i in range(50):
        rule.evaluate(h.ctx(event(t=T0 + i, identity=user_identity(f"u{i}"))))
    assert rule.state_size() == 5


def test_disabled_rule_is_silent() -> None:
    config = Config().with_overrides({"travel.enabled": False})
    rule = ImpossibleTravelRule(config)
    h = Harness(config)
    run(h, rule, HQ_IP, T0)
    assert run(h, rule, HOSTILE_AMS_IP, T0 + 60) == []
