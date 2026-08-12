import json
import warnings
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from disposable_email_score import evaluate_email
from disposable_email_score.models import RiskLevel

# ---------------------------------------------------------
# Phase 1: Public SDK Tests
# ---------------------------------------------------------


def test_offline_evaluation():
    """Test that evaluating without an API key correctly uses the offline algorithms."""
    # A known disposable domain from the open-source list
    result = evaluate_email("test@mailinator.com")

    assert result.decision == RiskLevel.BLOCK
    assert result.score >= 0.7
    assert "known_disposable_domain" in result.reasons


def test_live_evaluation_success():
    """Test that a successful live API response is parsed correctly."""
    mock_response_data = {
        "decision": "allow",
        "score": 0.1,
        "thresholds": {"allow": 0.5, "block": 0.9},
        "signals": {"valid_mx": 0.0},
        "reasons": [],
    }

    # Mock urllib.request.urlopen to return a successful 200 response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(mock_response_data).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = evaluate_email(
            email="test@gmail.com", api_key="dsk_live_mock123", api_url="https://api.signguard.co"
        )

        assert result.decision == RiskLevel.ALLOW
        assert result.score == 0.1
        mock_urlopen.assert_called_once()


def test_live_evaluation_429_fallback():
    """Test that a 429 Too Many Requests error gracefully falls back to offline evaluation."""
    # Create a mock HTTPError with code 429
    error_429 = HTTPError(url="mock", hdrs=None, fp=None, code=429, msg="Too Many Requests")

    with patch("urllib.request.urlopen", side_effect=error_429):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Use a known disposable domain to verify offline fallback worked
            result = evaluate_email(email="test@guerrillamail.com", api_key="dsk_live_mock123")

            # Verify the result fell back to offline correctly
            assert result.decision == RiskLevel.BLOCK
            assert "known_disposable_domain" in result.reasons

            # Verify the warning message is exactly our custom 429 warning
            assert len(w) >= 1
            warning_messages = [str(warning.message) for warning in w]
            assert any(
                "SignGuard API rate limit exceeded (HTTP 429)" in msg for msg in warning_messages
            )


def test_live_evaluation_timeout_fallback():
    """Test that a timeout cleanly falls back to offline validation."""
    timeout_error = URLError("timeout")

    with patch("urllib.request.urlopen", side_effect=timeout_error):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            result = evaluate_email(email="test@10minutemail.com", api_key="dsk_live_mock123")

            assert result.decision == RiskLevel.BLOCK

            assert len(w) >= 1
            warning_messages = [str(warning.message) for warning in w]
            assert any(
                "Falling back to local offline domain list" in msg for msg in warning_messages
            )


def test_malformed_api_key_warning():
    """Test that a malformed API key triggers a developer warning but still falls back."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        evaluate_email("test@gmail.com", api_key="invalid_key_format")

        assert len(w) >= 1
        warning_messages = [str(warning.message) for warning in w]
        assert any("API key format looks invalid" in msg for msg in warning_messages)
