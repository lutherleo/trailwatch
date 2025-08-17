"""Rules-as-code tests: behavioural novelty against the baseline."""

from __future__ import annotations

from conftest import (
    BOTO_UA,
    DALLAS_HOSTING_IP,
    HOME_IP,
    HOSTILE_AMS_IP,
    HQ_IP,
    T0,
    Harness,
    event,
    user_identity,
)
from trailwatch.config import Config
from trailwatch.model import Severity
from trailwatch.rules import NoveltyRule

KALI_UA = "aws-cli/1.32.1 Python/3.11.8 Linux/6.6.9-amd64-kali botocore/1.34.1"


def titles(h: Harness, **kwargs: object) -> dict[str, Severity]:
    rule = NoveltyRule(h.config)
    ev = event(**kwargs)  # type: ignore[arg-type]
    return {f.title: f.severity for f in rule.evaluate(h.ctx(ev))}


def test_cold_principal_produces_no_novelty(harness: Harness) -> None:
    assert titles(harness, ip=HOSTILE_AMS_IP, ua=BOTO_UA, region="sa-east-1") == {}


def test_offensive_distribution_is_high_even_when_cold(harness: Harness) -> None:
    assert titles(harness, ua=KALI_UA) == {
        "Call from a penetration-testing distribution": Severity.HIGH
    }


def test_new_country_from_hosting_is_bumped() -> None:
    h = Harness()
    h.warm()
    found = titles(h, ip=HOSTILE_AMS_IP, t=T0 + 1)
    assert found == {"First call from country NL": Severity.HIGH}


def test_new_asn_same_country() -> None:
    h = Harness()
    h.warm()
    assert titles(h, ip=HOME_IP, t=T0 + 1) == {"First call from network AS64520": Severity.LOW}
    assert titles(h, ip=DALLAS_HOSTING_IP, t=T0 + 1) == {
        "First call from network AS64552": Severity.MEDIUM
    }


def test_new_ua_family_and_region() -> None:
    h = Harness()
    h.warm()
    found = titles(h, ua=BOTO_UA, region="eu-west-1", t=T0 + 1)
    assert found["New user-agent family boto3"] == Severity.MEDIUM
    # eu-west-1 was never used in the account at all -> bumped from low to medium.
    assert found["First use of region eu-west-1"] == Severity.MEDIUM


def test_region_known_to_account_is_low() -> None:
    h = Harness()
    h.warm()
    h.learn(event(region="eu-west-1", t=T0 - 100, identity=user_identity("bob")))
    found = titles(h, region="eu-west-1", t=T0 + 1)
    assert found == {"First use of region eu-west-1": Severity.LOW}


def test_sensitive_and_rare_apis() -> None:
    h = Harness()
    h.warm()
    sensitive = titles(h, name="GetSecretValue", source="secretsmanager", t=T0 + 1)
    assert sensitive == {
        "First use of sensitive API secretsmanager:GetSecretValue": Severity.MEDIUM
    }
    rare = titles(h, name="ListHostedZones", source="route53", t=T0 + 1)
    assert rare == {"First use of rare API route53:ListHostedZones": Severity.LOW}


def test_api_common_in_account_is_not_rare() -> None:
    h = Harness()
    h.warm()
    h.warm(user="bob", apis=(("ListHostedZones", "route53"),), per_day=50)
    assert titles(h, name="ListHostedZones", source="route53", t=T0 + 1) == {}


def test_familiar_activity_is_quiet() -> None:
    h = Harness()
    h.warm()
    assert titles(h, ip=HQ_IP, t=T0 + 1) == {}


def test_disabled() -> None:
    h = Harness(Config().with_overrides({"novelty.enabled": False}))
    h.warm()
    assert titles(h, ua=KALI_UA, ip=HOSTILE_AMS_IP) == {}
