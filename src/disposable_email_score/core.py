"""
Core evaluation logic for email risk scoring.
"""

from typing import Dict

from .config import SCORES, THRESHOLD_BLOCK, THRESHOLD_REVIEW
from .models import RiskLevel, RiskResult
from .signals import (
    check_disposable,
    check_mx_records,
    check_role_account,
    check_structure,
    check_typosquatting,
)


def evaluate_email(email: str) -> RiskResult:
    """
    Evaluates an email address and returns a detailed risk result.

    Args:
        email: The email address to evaluate

    Returns:
        RiskResult with decision, score, signals, and reasons
    """
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
