"""
Configuration constants and scoring weights for the risk engine.
"""

# Decision thresholds
THRESHOLD_BLOCK = 0.7
THRESHOLD_REVIEW = 0.3

# Signal weights (risk scores)
SCORES = {
    "disposable_domain": 0.7,  # Known disposable/temp email domain
    "typosquatting": 0.6,  # Domain looks like a typo of major provider
    "no_mx_records": 0.5,  # Domain has no MX records
    "risky_mx": 0.3,  # MX records match risky patterns
    "role_account": 0.2,  # Role-based email (admin@, info@, etc.)
    "mx_lookup_error": 0.1,  # Generic DNS error
    "plus_alias": 0.05,  # Email uses +tag alias
    "new_domain": 0.2,  # Domain less than 30 days old (unused)
    "invalid_format": 1.0,  # Not a valid email format
}

# Role account prefixes (shared inboxes, not personal emails)
ROLE_PREFIXES = {
    "admin", "administrator", "info", "information", "sales", "support",
    "contact", "help", "billing", "noreply", "no-reply", "donotreply",
    "postmaster", "webmaster", "hostmaster", "abuse", "security",
    "marketing", "press", "media", "hr", "careers", "jobs", "legal",
    "feedback", "enquiry", "enquiries", "hello", "office", "team",
}

# Risky MX patterns to check against
RISKY_MX_PATTERNS = ["temp", "disposable", "guerrillamail", "throwaway"]

# MX cache settings
MX_CACHE_SIZE = 1024  # Max domains to cache

# Major email providers to check typosquatting against
MAJOR_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "protonmail.com",
    "aol.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
}

# Typosquatting detection: flag domains that are 80-99% similar to major providers
# (100% = exact match = legitimate, so not flagged)
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.8
