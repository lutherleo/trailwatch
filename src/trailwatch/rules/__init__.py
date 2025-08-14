"""Detection rules (rules as code). :func:`default_rules` builds the shipped rule set."""

from __future__ import annotations

from trailwatch.config import Config
from trailwatch.rules.access_keys import AccessKeyCreationRule
from trailwatch.rules.base import EventContext, Rule
from trailwatch.rules.console_mfa import ConsoleNoMfaRule
from trailwatch.rules.enumeration import EnumerationBurstRule
from trailwatch.rules.logging_tamper import LoggingTamperRule
from trailwatch.rules.novelty import NoveltyRule
from trailwatch.rules.travel import ImpossibleTravelRule

RULE_CLASSES: tuple[type[Rule], ...] = (
    ImpossibleTravelRule,
    ConsoleNoMfaRule,
    AccessKeyCreationRule,
    EnumerationBurstRule,
    LoggingTamperRule,
    NoveltyRule,
)


def default_rules(config: Config) -> list[Rule]:
    return [cls(config) for cls in RULE_CLASSES]


__all__ = [
    "RULE_CLASSES",
    "AccessKeyCreationRule",
    "ConsoleNoMfaRule",
    "EnumerationBurstRule",
    "EventContext",
    "ImpossibleTravelRule",
    "LoggingTamperRule",
    "NoveltyRule",
    "Rule",
    "default_rules",
]
