"""Typed configuration loaded from TOML, with validation and dotted-path overrides.

Every tunable lives here so detection logic never hard-codes a threshold. Unknown keys are
rejected (a typo in a security config should fail loudly, not silently fall back to a default).
"""

from __future__ import annotations

import dataclasses
import tomllib
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trailwatch.model import Severity


class ConfigError(ValueError):
    """Invalid configuration."""


@dataclass(frozen=True)
class IngestConfig:
    max_lateness_seconds: float = 900.0
    max_buffer: int = 200_000


@dataclass(frozen=True)
class BaselineConfig:
    half_life_days: float = 30.0
    warmup_days: float = 7.0
    warmup_events: int = 50
    familiar_min_weight: float = 3.0
    suppress_familiar: bool = True
    max_principals: int = 50_000
    max_apis: int = 512
    max_regions: int = 32
    max_ua_families: int = 16
    max_asns: int = 64
    max_countries: int = 32


@dataclass(frozen=True)
class TravelConfig:
    enabled: bool = True
    max_speed_kmh: float = 1000.0
    min_distance_km: float = 500.0
    severity: Severity = Severity.HIGH


@dataclass(frozen=True)
class ConsoleMfaConfig:
    enabled: bool = True
    window_minutes: float = 120.0
    login_severity: Severity = Severity.LOW
    change_severity: Severity = Severity.CRITICAL


@dataclass(frozen=True)
class AccessKeyConfig:
    enabled: bool = True
    routine_min_weight: float = 1.5


@dataclass(frozen=True)
class EnumerationConfig:
    enabled: bool = True
    window_minutes: float = 10.0
    min_distinct_apis: int = 20
    min_services: int = 4
    min_denied: int = 12
    peak_margin: float = 1.25
    max_window_items: int = 2000


@dataclass(frozen=True)
class LoggingTamperConfig:
    enabled: bool = True
    allowlist_trail_prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class NoveltyConfig:
    enabled: bool = True
    region_severity: Severity = Severity.LOW
    ua_family_severity: Severity = Severity.MEDIUM
    asn_severity: Severity = Severity.LOW
    country_severity: Severity = Severity.MEDIUM
    rare_api_severity: Severity = Severity.LOW
    sensitive_api_severity: Severity = Severity.MEDIUM
    global_rare_share: float = 0.002
    sensitive_apis: tuple[str, ...] = (
        "secretsmanager:GetSecretValue",
        "ssm:GetParameters",
        "ssm:GetParameter",
        "kms:Decrypt",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:AttachRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "sts:GetFederationToken",
        "s3:PutBucketPolicy",
        "s3:PutBucketAcl",
        "ec2:ModifySnapshotAttribute",
        "ec2:CreateKeyPair",
        "ec2:ImportKeyPair",
    )


@dataclass(frozen=True)
class ScoringConfig:
    half_life_hours: float = 6.0
    threshold: float = 60.0
    weight_info: float = 0.0
    weight_low: float = 10.0
    weight_medium: float = 25.0
    weight_high: float = 50.0
    weight_critical: float = 80.0
    max_contributions: int = 32
    direct_alert_severity: Severity = Severity.HIGH

    def weight(self, severity: Severity) -> float:
        return {
            Severity.INFO: self.weight_info,
            Severity.LOW: self.weight_low,
            Severity.MEDIUM: self.weight_medium,
            Severity.HIGH: self.weight_high,
            Severity.CRITICAL: self.weight_critical,
        }[severity]


@dataclass(frozen=True)
class DedupConfig:
    ttl_hours: float = 12.0
    max_entries: int = 100_000
    max_evidence: int = 50


@dataclass(frozen=True)
class StateConfig:
    max_rule_principals: int = 50_000


@dataclass(frozen=True)
class Config:
    ingest: IngestConfig = field(default_factory=IngestConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    travel: TravelConfig = field(default_factory=TravelConfig)
    console_mfa: ConsoleMfaConfig = field(default_factory=ConsoleMfaConfig)
    access_keys: AccessKeyConfig = field(default_factory=AccessKeyConfig)
    enumeration: EnumerationConfig = field(default_factory=EnumerationConfig)
    logging_tamper: LoggingTamperConfig = field(default_factory=LoggingTamperConfig)
    novelty: NoveltyConfig = field(default_factory=NoveltyConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)
    state: StateConfig = field(default_factory=StateConfig)

    def __post_init__(self) -> None:
        _validate(self)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Config:
        return _build(cls, data, "")

    @classmethod
    def load(cls, path: str | Path) -> Config:
        try:
            with Path(path).open("rb") as handle:
                data = tomllib.load(handle)
        except OSError as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
        return cls.from_mapping(data)

    def with_overrides(self, overrides: dict[str, Any]) -> Config:
        """Return a copy with ``{"section.key": value}`` overrides applied (values coerced)."""
        data = to_mapping(self)
        for dotted, value in overrides.items():
            section, _, key = dotted.partition(".")
            if not key or section not in data or key not in data[section]:
                raise ConfigError(f"unknown config key {dotted!r}")
            data[section][key] = value
        return Config.from_mapping(data)


def to_mapping(config: Config) -> dict[str, dict[str, Any]]:
    """Plain-dict view of a config (severities as names), suitable for TOML/JSON output."""
    out: dict[str, dict[str, Any]] = {}
    for section in dataclasses.fields(config):
        values = {}
        for f in dataclasses.fields(getattr(config, section.name)):
            value = getattr(getattr(config, section.name), f.name)
            if isinstance(value, Severity):
                value = value.label
            elif isinstance(value, tuple):
                value = list(value)
            values[f.name] = value
        out[section.name] = values
    return out


def parse_override(text: str) -> tuple[str, Any]:
    """Parse ``section.key=value`` (value parsed as a TOML scalar, else kept as a string)."""
    key, sep, raw = text.partition("=")
    if not sep or not key.strip():
        raise ConfigError(f"override must look like section.key=value, got {text!r}")
    try:
        value = tomllib.loads(f"v = {raw.strip()}")["v"]
    except tomllib.TOMLDecodeError:
        value = raw.strip()
    return key.strip(), value


def _coerce(expected: Any, value: Any, where: str) -> Any:
    origin = typing.get_origin(expected)
    if expected is Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            try:
                return Severity.parse(value)
            except ValueError as exc:
                raise ConfigError(f"{where}: {exc}") from exc
        raise ConfigError(f"{where}: expected a severity name, got {value!r}")
    if expected is bool:
        if isinstance(value, bool):
            return value
        raise ConfigError(f"{where}: expected true/false, got {value!r}")
    if expected is int:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        raise ConfigError(f"{where}: expected an integer, got {value!r}")
    if expected is float:
        if isinstance(value, int | float) and not isinstance(value, bool):
            return float(value)
        raise ConfigError(f"{where}: expected a number, got {value!r}")
    if expected is str:
        if isinstance(value, str):
            return value
        raise ConfigError(f"{where}: expected a string, got {value!r}")
    if origin is tuple:
        if isinstance(value, list | tuple) and all(isinstance(v, str) for v in value):
            return tuple(value)
        raise ConfigError(f"{where}: expected a list of strings, got {value!r}")
    if dataclasses.is_dataclass(expected) and isinstance(expected, type):
        if not isinstance(value, dict):
            raise ConfigError(f"{where}: expected a table, got {value!r}")
        return _build(expected, value, where)
    raise ConfigError(f"{where}: unsupported config type {expected!r}")  # pragma: no cover


def _build[T](cls: type[T], data: dict[str, Any], prefix: str) -> T:
    if not dataclasses.is_dataclass(cls):  # pragma: no cover - programming error
        raise TypeError(f"{cls!r} is not a dataclass")
    hints = typing.get_type_hints(cls)
    known = {f.name for f in dataclasses.fields(cls)}
    unknown = sorted(set(data) - known)
    if unknown:
        where = prefix or "top level"
        raise ConfigError(f"unknown config key(s) in {where}: {', '.join(unknown)}")
    kwargs = {
        name: _coerce(hints[name], value, f"{prefix}.{name}" if prefix else name)
        for name, value in data.items()
    }
    return cls(**kwargs)


def _validate(config: Config) -> None:
    positive = {
        "ingest.max_lateness_seconds": config.ingest.max_lateness_seconds,
        "ingest.max_buffer": config.ingest.max_buffer,
        "baseline.half_life_days": config.baseline.half_life_days,
        "baseline.max_principals": config.baseline.max_principals,
        "baseline.max_apis": config.baseline.max_apis,
        "travel.max_speed_kmh": config.travel.max_speed_kmh,
        "console_mfa.window_minutes": config.console_mfa.window_minutes,
        "enumeration.window_minutes": config.enumeration.window_minutes,
        "enumeration.min_distinct_apis": config.enumeration.min_distinct_apis,
        "enumeration.max_window_items": config.enumeration.max_window_items,
        "scoring.half_life_hours": config.scoring.half_life_hours,
        "scoring.threshold": config.scoring.threshold,
        "scoring.max_contributions": config.scoring.max_contributions,
        "dedup.ttl_hours": config.dedup.ttl_hours,
        "dedup.max_entries": config.dedup.max_entries,
        "dedup.max_evidence": config.dedup.max_evidence,
        "state.max_rule_principals": config.state.max_rule_principals,
    }
    for name, value in positive.items():
        if value <= 0:
            raise ConfigError(f"{name} must be > 0 (got {value})")
    if config.baseline.warmup_days < 0 or config.baseline.warmup_events < 0:
        raise ConfigError("baseline warmup values must be >= 0")
    if not 0 <= config.novelty.global_rare_share <= 1:
        raise ConfigError("novelty.global_rare_share must be within [0, 1]")
    if config.enumeration.peak_margin < 1:
        raise ConfigError("enumeration.peak_margin must be >= 1")
