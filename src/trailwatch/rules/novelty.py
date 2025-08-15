"""Behavioural novelty against the per-principal baseline.

Each signal fires the first time a *warmed-up* principal does something outside its decayed
history: a new region, a new user-agent family, a new network or country, or an API it has
never called that is also rare (or sensitive) account-wide. Individually these are weak; the
risk scorer is what turns several of them in a short time into an alert.
"""

from __future__ import annotations

from trailwatch.baseline import Dim
from trailwatch.model import Finding, Severity
from trailwatch.rules.base import EventContext, Rule

OFFENSIVE_FAMILY = "offensive-distro"


class NoveltyRule(Rule):
    rule_id = "behavioral_novelty"
    description = (
        "First-seen region / user-agent family / ASN / country / rare-or-sensitive API for a "
        "warmed-up principal. A penetration-testing distribution in the user agent is high "
        "severity regardless of baseline state."
    )
    techniques = ("T1078.004",)

    def evaluate(self, ctx: EventContext) -> list[Finding]:
        cfg = self.config.novelty
        if not cfg.enabled:
            return []
        findings: list[Finding] = []
        if ctx.ua_family == OFFENSIVE_FAMILY:
            findings.append(
                self.finding(
                    ctx,
                    Severity.HIGH,
                    "Call from a penetration-testing distribution",
                    f"user agent {ctx.event.user_agent[:120]!r}",
                    dedup_key=OFFENSIVE_FAMILY,
                    attrs={"ua_family": ctx.ua_family},
                )
            )
        profile = ctx.profile
        if profile is None or not ctx.warmed_up:
            return findings
        event = ctx.event
        now = ctx.now

        if profile.is_new(Dim.REGION, event.region):
            severity = cfg.region_severity
            account_new = event.region not in ctx.baseline.global_stats.regions
            if account_new:
                severity = severity.bump(1)
            findings.append(
                self.finding(
                    ctx,
                    severity,
                    f"First use of region {event.region}",
                    "region never used by this principal"
                    + (" or by anyone in the account" if account_new else ""),
                    dedup_key=f"region:{event.region}",
                    attrs={"region": event.region, "account_new": account_new},
                )
            )
        if ctx.ua_family != OFFENSIVE_FAMILY and profile.is_new(Dim.UA, ctx.ua_family):
            findings.append(
                self.finding(
                    ctx,
                    cfg.ua_family_severity,
                    f"New user-agent family {ctx.ua_family}",
                    f"user agent {event.user_agent[:120]!r}",
                    dedup_key=f"ua:{ctx.ua_family}",
                    attrs={"ua_family": ctx.ua_family},
                )
            )
        net = ctx.net
        if net is not None:
            hosting = net.kind == "hosting"
            if profile.is_new(Dim.COUNTRY, net.country):
                findings.append(
                    self.finding(
                        ctx,
                        cfg.country_severity.bump(1 if hosting else 0),
                        f"First call from country {net.country}",
                        f"{net.asn_label} {net.org} ({net.kind}) in {ctx.location}",
                        dedup_key=f"country:{net.country}",
                        attrs={"asn": net.asn, "country": net.country, "kind": net.kind},
                    )
                )
            elif profile.is_new(Dim.ASN, net.asn_label):
                findings.append(
                    self.finding(
                        ctx,
                        cfg.asn_severity.bump(1 if hosting else 0),
                        f"First call from network {net.asn_label}",
                        f"{net.org} ({net.kind}) in {ctx.location}",
                        dedup_key=f"asn:{net.asn}",
                        attrs={"asn": net.asn, "kind": net.kind},
                    )
                )
        if profile.is_new(Dim.API, event.api):
            sensitive = event.api in cfg.sensitive_apis
            share = ctx.baseline.global_stats.api_share(event.api, now)
            if sensitive or share < cfg.global_rare_share:
                findings.append(
                    self.finding(
                        ctx,
                        cfg.sensitive_api_severity if sensitive else cfg.rare_api_severity,
                        f"First use of {'sensitive' if sensitive else 'rare'} API {event.api}",
                        f"account-wide share of calls {share:.4%}",
                        dedup_key=f"api:{event.api}",
                        attrs={"api": event.api, "global_share": round(share, 6)},
                    )
                )
        return findings
