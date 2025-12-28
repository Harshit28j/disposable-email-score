# Disposable Email Score

A robust, explainable risk-scoring engine for email signups. Detects disposable emails, typosquatting attacks, and suspicious domains.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Twitter](https://img.shields.io/badge/Twitter-@harshitpy-1DA1F2?logo=twitter)](https://twitter.com/harshitpy)

## Features

- **Disposable Domain Detection** — Checks against 113,000+ known disposable email domains
- **Typosquatting Detection** — Catches fake domains like `gmaiil.com`, `yahooo.com`
- **MX Record Analysis** — Flags domains with missing or suspicious mail servers
- **Role Account Detection** — Flags shared inboxes like `admin@`, `info@`, `sales@`
- **Subdomain Detection** — Blocks `mail.tempmail.com` if `tempmail.com` is blocked
- **Plus Alias Detection** — Detects `user+tag@gmail.com` patterns
- **Allowlist Support** — Trusted domains bypass all checks
- **Explainable Output** — Returns score, decision, signals, and human-readable reasons

## 🚀 Hosted API (Coming Soon)

Don't want to self-host? We're building a hosted API with:
- Simple REST API — works with any language
- No setup required — get an API key and start
- Always updated blocklist

**[👉 Join the waitlist](https://tally.so/r/9qXkd1)** to get early access + lifetime discount.

## Installation

```bash
pip install disposable-email-score
```

## Quick Start

```python
from disposable_email_score import evaluate_email

result = evaluate_email("user@tempmail.xyz")
print(result.model_dump_json(indent=2))
```

### Output

```json
{
  "decision": "block",
  "score": 0.7,
  "thresholds": {
    "allow": 0.3,
    "block": 0.7
  },
  "signals": {
    "domain_in_blocklist": 0.7
  },
  "reasons": [
    "known_disposable_domain"
  ]
}
```

### Using RiskLevel

```python
from disposable_email_score import evaluate_email, RiskLevel

result = evaluate_email("test@example.com")

if result.decision == RiskLevel.BLOCK:
    print("❌ Blocked!")
elif result.decision == RiskLevel.REVIEW:
    print("🟡 Needs review")
else:
    print("✅ Allowed")
```

## How It Works

![Architecture](https://raw.githubusercontent.com/Harshit28j/disposable-email-score/main/docs/architecture.png)

## Risk Levels

| Score | Decision | Action |
|-------|----------|--------|
| < 0.3 | `allow` | Low risk — let them through |
| 0.3 - 0.69 | `review` | Medium risk — require CAPTCHA or verification |
| ≥ 0.7 | `block` | High risk — reject signup |

## Signals & Weights

| Signal | Weight | Description |
|--------|--------|-------------|
| `domain_in_blocklist` | 0.7 | Known disposable domain |
| `typosquatting` | 0.6 | Looks like a typo of gmail.com, yahoo.com, etc. |
| `mx_risky_or_missing` | 0.5 | No MX records or suspicious mail infrastructure |
| `plus_alias` | 0.05 | Uses `+tag` in local part |

## Framework Integration

### FastAPI

```python
from fastapi import FastAPI
from disposable_email_score import evaluate_email, RiskResult

app = FastAPI()

@app.get("/check-email", response_model=RiskResult)
def check_email(email: str):
    return evaluate_email(email)
```

### Django

```python
from django.http import JsonResponse
from disposable_email_score import evaluate_email

def validate_signup(request):
    email = request.GET.get('email')
    result = evaluate_email(email)
    
    if result.decision == "block":
        return JsonResponse({'error': 'Email not allowed'}, status=400)
    
    return JsonResponse(result.model_dump())
```

## Configuration

All weights and thresholds are in `config.py`:

```python
THRESHOLD_BLOCK = 0.7
THRESHOLD_REVIEW = 0.3

SCORES = {
    "disposable_domain": 0.7,
    "typosquatting": 0.6,
    "no_mx_records": 0.5,
    ...
}
```

## Auto-Updates

Domain lists are automatically updated weekly via GitHub Actions from [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains).

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
ruff format src/ tests/

# Lint
ruff check src/ tests/
```

## License

MIT
