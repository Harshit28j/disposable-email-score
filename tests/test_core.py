"""
Unit tests for disposable_email_score package.
"""

import sys
from pathlib import Path

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from disposable_email_score import RiskLevel, RiskResult, evaluate_email


class TestEvaluateEmail:
    """Tests for the main evaluate_email function."""

    def test_valid_gmail_address(self):
        """Gmail addresses should be allowed (low risk)."""
        result = evaluate_email("user@gmail.com")

        assert isinstance(result, RiskResult)
        assert result.decision == RiskLevel.ALLOW
        assert result.score < 0.3

    def test_disposable_domain_blocked(self):
        """Known disposable domains should be blocked."""
        result = evaluate_email("test@10minutemail.com")

        assert result.decision == RiskLevel.BLOCK
        assert result.score >= 0.7
        assert "domain_in_blocklist" in result.signals

    def test_invalid_email_format(self):
        """Invalid email format should be blocked."""
        result = evaluate_email("not-an-email")

        assert result.decision == RiskLevel.BLOCK
        assert result.score == 1.0
        assert "invalid_format" in result.signals

    def test_plus_alias_detected(self):
        """Plus aliases should add a small risk score."""
        result = evaluate_email("user+spam@gmail.com")

        assert "plus_alias" in result.signals
        assert result.signals["plus_alias"] == 0.05

    def test_allowlist_overrides_blocklist(self):
        """Domains in allowlist should not trigger blocklist."""
        # fastmail.com is in our allowlist
        result = evaluate_email("user@fastmail.com")

        assert "domain_in_blocklist" not in result.signals

    def test_result_has_thresholds(self):
        """Result should include threshold information."""
        result = evaluate_email("test@example.com")

        assert "allow" in result.thresholds
        assert "block" in result.thresholds
        assert result.thresholds["allow"] == 0.3
        assert result.thresholds["block"] == 0.7

    def test_result_is_json_serializable(self):
        """Result should be serializable to JSON."""
        result = evaluate_email("test@example.com")

        json_str = result.model_dump_json()
        assert isinstance(json_str, str)
        assert "decision" in json_str


class TestSignals:
    """Tests for individual signal functions."""

    def test_check_disposable_blocklist(self):
        """Blocklist domains should return risk score."""
        from disposable_email_score.signals import check_disposable

        assert check_disposable("10minutemail.com") == 0.7
        assert check_disposable("guerrillamail.com") == 0.7

    def test_check_disposable_allowlist(self):
        """Allowlist domains should return zero."""
        from disposable_email_score.signals import check_disposable

        assert check_disposable("fastmail.com") == 0.0
        assert check_disposable("hushmail.com") == 0.0

    def test_check_disposable_unknown(self):
        """Unknown domains should return zero."""
        from disposable_email_score.signals import check_disposable

        assert check_disposable("randomdomain12345.com") == 0.0

    def test_check_structure_plus_alias(self):
        """Plus aliases should be detected."""
        from disposable_email_score.signals import check_structure

        assert check_structure("user+tag") == 0.05
        assert check_structure("user") == 0.0

    def test_check_disposable_subdomain(self):
        """Subdomains of blocked domains should also be blocked."""
        from disposable_email_score.signals import check_disposable

        # If tempmail.com is blocked, mail.tempmail.com should be too
        # Using 10minutemail.com which is definitely in blocklist
        assert check_disposable("mail.10minutemail.com") == 0.7
        assert check_disposable("subdomain.guerrillamail.com") == 0.7

    def test_check_typosquatting_detects_typos(self):
        """Typosquatted domains should be detected."""
        from disposable_email_score.signals import check_typosquatting

        # gmaiil.com looks like gmail.com
        score, matched = check_typosquatting("gmaiil.com")
        assert score == 0.6
        assert matched == "gmail.com"

        # yahooo.com looks like yahoo.com
        score, matched = check_typosquatting("yahooo.com")
        assert score == 0.6
        assert matched == "yahoo.com"

    def test_check_typosquatting_allows_legit_providers(self):
        """Legitimate major providers should not be flagged."""
        from disposable_email_score.signals import check_typosquatting

        # Exact matches should return 0
        score, matched = check_typosquatting("gmail.com")
        assert score == 0.0
        assert matched is None

        score, matched = check_typosquatting("yahoo.com")
        assert score == 0.0
        assert matched is None

    def test_typosquatting_in_full_evaluation(self):
        """Typosquatting should be detected in full email evaluation."""
        result = evaluate_email("scammer@gmaiil.com")

        assert "typosquatting" in result.signals
        assert result.score >= 0.6
        assert any("typosquatting" in r for r in result.reasons)

    def test_check_role_account_detects_roles(self):
        """Role accounts should be detected."""
        from disposable_email_score.signals import check_role_account

        assert check_role_account("admin") == 0.2
        assert check_role_account("info") == 0.2
        assert check_role_account("sales") == 0.2
        assert check_role_account("support") == 0.2
        assert check_role_account("noreply") == 0.2

    def test_check_role_account_allows_normal(self):
        """Normal personal emails should not be flagged."""
        from disposable_email_score.signals import check_role_account

        assert check_role_account("john") == 0.0
        assert check_role_account("harshit") == 0.0
        assert check_role_account("user123") == 0.0

    def test_role_account_in_full_evaluation(self):
        """Role accounts should be detected in full email evaluation."""
        result = evaluate_email("admin@gmail.com")

        assert "role_account" in result.signals
        assert result.signals["role_account"] == 0.2


class TestRiskLevels:
    """Tests for risk level thresholds."""

    def test_score_below_review_threshold_is_allow(self):
        """Scores below 0.3 should be ALLOW."""
        result = evaluate_email("user@gmail.com")

        if result.score < 0.3:
            assert result.decision == RiskLevel.ALLOW

    def test_score_above_block_threshold_is_block(self):
        """Scores at or above 0.7 should be BLOCK."""
        result = evaluate_email("test@10minutemail.com")

        if result.score >= 0.7:
            assert result.decision == RiskLevel.BLOCK
