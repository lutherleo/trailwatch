"""User-agent family classification.

Baselines track user-agent *families* rather than raw strings: SDK and OS version bumps change
the raw string every few weeks, which would make "new user agent" fire constantly, whereas a
principal that has only ever used Terraform suddenly calling from a raw HTTP client is a real
behavioural change.
"""

from __future__ import annotations

from functools import lru_cache

# Ordered: first match wins. Patterns are matched against the lower-cased user agent.
_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("offensive-distro", ("kali", "parrot", "pentoo", "blackarch")),
    ("terraform", ("terraform/", "hashicorp")),
    ("aws-cli", ("aws-cli/",)),
    ("powershell", ("awspowershell",)),
    ("aws-sdk-go", ("aws-sdk-go",)),
    ("aws-sdk-java", ("aws-sdk-java",)),
    ("aws-sdk-js", ("aws-sdk-js", "aws-sdk-nodejs")),
    ("boto3", ("boto3/", "botocore/")),
    ("console", ("signin.amazonaws.com", "console.amazonaws.com", "console.")),
    ("aws-internal", ("aws internal", "awsinternal")),
    ("scripted-http", ("curl/", "python-requests", "go-http-client", "wget/", "okhttp")),
    ("browser", ("mozilla/",)),
)

KNOWN_FAMILIES: tuple[str, ...] = (
    *(name for name, _ in _RULES),
    "aws-service",
    "unknown",
)

# Families that indicate an interactive human session rather than automation.
INTERACTIVE_FAMILIES = frozenset({"console", "browser"})


@lru_cache(maxsize=4096)
def classify(user_agent: str) -> str:
    """Map a raw ``userAgent`` value to a coarse, stable family name."""
    ua = user_agent.strip().lower()
    if not ua:
        return "unknown"
    for family, needles in _RULES:
        if any(needle in ua for needle in needles):
            return family
    if ua.endswith(".amazonaws.com") and " " not in ua:
        return "aws-service"
    return "unknown"
