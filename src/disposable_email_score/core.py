"""
Core evaluation logic for email risk scoring.
"""

import json
import os
import urllib.error
import urllib.request
import warnings
from typing import Dict, Optional

from .config import SCORES, THRESHOLD_BLOCK, THRESHOLD_REVIEW
from .models import RiskLevel, RiskResult
from .signals import (
    check_disposable,
    check_mx_records,
    check_role_account,
    check_structure,
    check_typosquatting,
)


def evaluate_email(
    email: str,
    api_key: Optional[str] = None,
    api_url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> RiskResult:
    """
    Evaluates an email address and returns a detailed risk result.

    Args:
        email: The email address to evaluate
        api_key: Optional API key for SignGuard live validation
        api_url: Optional API host for live validation (default: https://api.signguard.co)
        timeout: Optional request timeout in seconds (default: 3.0)

    Returns:
        RiskResult with decision, score, signals, and reasons
    """
    if len(email) > 320:
        return RiskResult(
            decision=RiskLevel.BLOCK,
            score=1.0,
            thresholds={"allow": THRESHOLD_REVIEW, "block": THRESHOLD_BLOCK},
            signals={"invalid_format": SCORES["invalid_format"]},
            reasons=["Email address too long"],
        )

    # Resolve API Key
    resolved_api_key = api_key or os.environ.get("SIGNGUARD_API_KEY")
    if resolved_api_key and isinstance(resolved_api_key, str) and resolved_api_key.strip():
        resolved_api_key = resolved_api_key.strip()

        # Check API key prefix for quick developer warning
        if not resolved_api_key.startswith("dsk_live_"):
            try:
                warnings.warn(
                    "API key format looks invalid. SignGuard keys typically start with 'dsk_live_'.",
                    RuntimeWarning,
                    stacklevel=2,
                )
            except Exception:
                pass

        # Resolve API URL
        resolved_api_url = (
            api_url or os.environ.get("SIGNGUARD_API_URL") or "https://api.signguard.co"
        )
        parsed_url = resolved_api_url.lower().strip()

        # Resolve Timeout
        resolved_timeout = timeout
        if resolved_timeout is None:
            try:
                resolved_timeout = float(os.environ.get("SIGNGUARD_TIMEOUT", 3.0))
            except ValueError:
                resolved_timeout = 3.0

        # Enforce HTTPS unless localhost/127.0.0.1 for safety
        if not (
            parsed_url.startswith("https://")
            or "localhost" in parsed_url
            or "127.0.0.1" in parsed_url
        ):
            try:
                warnings.warn(
                    "Insecure api_url protocol. SignGuard live checks require HTTPS. Falling back to offline validation.",
                    RuntimeWarning,
                    stacklevel=2,
                )
            except Exception:
                pass
        else:
            try:
                url = f"{resolved_api_url.rstrip('/')}/v1/check"
                req_data = json.dumps({"email": email}).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=req_data,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {resolved_api_key}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=resolved_timeout) as response:
                    # DoS Protection: Limit response read to 8KB
                    res_body = response.read(8192).decode("utf-8")
                    res_data = json.loads(res_body)
                    # Let Pydantic handle validation, coercion, and raise ValidationError if malformed
                    return RiskResult(**res_data)
            except Exception as e:
                # Sanitize error message to avoid API key leaks
                err_msg = str(e)
                if resolved_api_key in err_msg:
                    err_msg = err_msg.replace(resolved_api_key, "******")
                try:
                    if hasattr(e, "code") and e.code == 429:
                        warnings.warn(
                            "SignGuard API rate limit exceeded (HTTP 429). "
                            "Falling back to local offline domain list and basic validation.",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                    else:
                        warnings.warn(
                            f"SignGuard live email check failed ({type(e).__name__}: {err_msg}). "
                            "Falling back to local offline domain list and basic validation.",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                except Exception:
                    pass

    reasons = []
    signals: Dict[str, float] = {}
    score = 0.0

    try:
        local_part, domain = email.split("@")
        domain = domain.lower()
    except ValueError:
        # Invalid email format
        return RiskResult(
            decision=RiskLevel.BLOCK,
            score=1.0,
            thresholds={"allow": THRESHOLD_REVIEW, "block": THRESHOLD_BLOCK},
            signals={"invalid_format": SCORES["invalid_format"]},
            reasons=["Invalid email format"],
        )

    # 1. Disposable Check (includes subdomain detection)
    disp_score = check_disposable(domain)
    if disp_score > 0:
        score += disp_score
        signals["domain_in_blocklist"] = disp_score
        reasons.append("known_disposable_domain")

    # 2. Typosquatting Check (e.g., gmaiil.com looks like gmail.com)
    typo_score, matched_provider = check_typosquatting(domain)
    if typo_score > 0:
        score += typo_score
        signals["typosquatting"] = typo_score
        reasons.append(f"typosquatting_detected:{matched_provider}")

    # 3. MX Check (cached for performance)
    mx_score = check_mx_records(domain)
    if mx_score > 0:
        score += mx_score
        signals["mx_risky_or_missing"] = mx_score
        reasons.append("suspicious_mx_infrastructure")

    # 4. Structure Check
    struct_score = check_structure(local_part)
    if struct_score > 0:
        score += struct_score
        signals["plus_alias"] = struct_score
        reasons.append("plus_alias_detected")

    # 5. Role Account Check (admin@, info@, sales@, etc.)
    role_score = check_role_account(local_part)
    if role_score > 0:
        score += role_score
        signals["role_account"] = role_score
        reasons.append("role_account_detected")

    # Determine Decision
    score = min(round(score, 2), 1.0)

    if score >= THRESHOLD_BLOCK:
        decision = RiskLevel.BLOCK
    elif score >= THRESHOLD_REVIEW:
        decision = RiskLevel.REVIEW
    else:
        decision = RiskLevel.ALLOW

    return RiskResult(
        decision=decision,
        score=score,
        thresholds={"allow": THRESHOLD_REVIEW, "block": THRESHOLD_BLOCK},
        signals=signals,
        reasons=reasons,
    )
