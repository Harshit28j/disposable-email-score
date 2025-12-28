"""
Signal functions for checking email risk factors.

Each function returns a risk score (float) that contributes to the total email risk.
"""

from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

import dns.resolver

from .config import (
    MAJOR_EMAIL_PROVIDERS,
    MX_CACHE_SIZE,
    RISKY_MX_PATTERNS,
    ROLE_PREFIXES,
    SCORES,
    TYPOSQUAT_SIMILARITY_THRESHOLD,
)


def load_domains_from_file(filename: str) -> set:
    """Loads a set of domains from a config file."""
    data_path = Path(__file__).parent / "data" / filename
    try:
        with open(data_path, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


DISPOSABLE_DOMAINS = load_domains_from_file("email_block_list.conf")
ALLOWED_DOMAINS = load_domains_from_file("allow_email_list.conf")


def check_disposable(domain: str) -> float:
    """Returns risk score component for disposable domain.

    Checks allowlist first - if domain is trusted, returns 0.
    Then checks blocklist for known disposable domains.
    Also checks parent domain for subdomains (e.g., mail.tempmail.com -> tempmail.com).
    """
    # Allowlist takes priority - trusted domains bypass blocklist
    if domain in ALLOWED_DOMAINS:
        return 0.0

    # Direct blocklist check
    if domain in DISPOSABLE_DOMAINS:
        return SCORES["disposable_domain"]

    # Subdomain check: mail.tempmail.com -> check tempmail.com
    parts = domain.split(".")
    if len(parts) > 2:
        parent_domain = ".".join(parts[-2:])
        if parent_domain in DISPOSABLE_DOMAINS and parent_domain not in ALLOWED_DOMAINS:
            return SCORES["disposable_domain"]

    return 0.0


@lru_cache(maxsize=MX_CACHE_SIZE)
def check_mx_records(domain: str) -> float:
    """Checks if MX records exist and if they look risky.

    Results are cached to avoid repeated DNS lookups for the same domain.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)  # 5 second timeout
        if not answers:
            return SCORES["no_mx_records"]

        # Check for known risky patterns in MX hostnames
        mx_hosts = [str(r.exchange).lower().rstrip(".") for r in answers]

        for host in mx_hosts:
            if any(pattern in host for pattern in RISKY_MX_PATTERNS):
                return SCORES["risky_mx"]

        return 0.0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
        return SCORES["no_mx_records"]
    except Exception:
        return SCORES["mx_lookup_error"]


def check_structure(local_part: str) -> float:
    """Checks for suspicious email structure."""
    if "+" in local_part:
        return SCORES["plus_alias"]
    return 0.0


def check_role_account(local_part: str) -> float:
    """Detects role-based email accounts (admin@, info@, sales@, etc.).

    Role accounts are shared inboxes that don't belong to a single person.
    They're often used for bulk signups or abuse.
    """
    # Strip plus alias if present (admin+tag -> admin)
    prefix = local_part.split("+")[0].lower()
    if prefix in ROLE_PREFIXES:
        return SCORES["role_account"]
    return 0.0


def check_typosquatting(domain: str) -> Tuple[float, Optional[str]]:
    """Detects typosquatted domains that look like major email providers.

    Uses string similarity matching to find domains that are suspiciously
    similar to gmail.com, yahoo.com, etc. but not exact matches.

    Examples:
        gmaiil.com  -> 91% similar to gmail.com -> FLAGGED
        gmai1.com   -> 80% similar to gmail.com -> FLAGGED
        gmail.com   -> 100% exact match -> NOT flagged (it's legit)
        example.com -> 40% similar -> NOT flagged (too different)

    Returns:
        Tuple of (risk_score, matched_provider or None)
    """
    # Exact match with a major provider = legitimate, no risk
    if domain in MAJOR_EMAIL_PROVIDERS:
        return 0.0, None

    # Check similarity against each major provider
    best_match = None
    highest_similarity = 0.0

    for provider in MAJOR_EMAIL_PROVIDERS:
        similarity = SequenceMatcher(None, domain, provider).ratio()

        if similarity > highest_similarity:
            highest_similarity = similarity
            best_match = provider

    # Flag if similarity is high but not exact (typosquat territory)
    if TYPOSQUAT_SIMILARITY_THRESHOLD <= highest_similarity < 1.0:
        return SCORES["typosquatting"], best_match

    return 0.0, None
