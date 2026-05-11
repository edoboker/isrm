# isrm — Product Specification

## What it is

**isrm** (internet service risk manager) is a CLI tool for CISOs operating in public clouds (AWS, GCP) to assess, track, and manage the risk of opening VPCs to external FQDNs, services, and third parties.

---

## Phased Roadmap

### Phase 1 — MVP: Risk Estimation (current)
Given a FQDN or URL, produce a structured risk assessment using automated enrichment and agentic research.

### Phase 2 — Attack Vectors
For each risk finding, generate a structured set of attack vectors (threat scenarios) relevant to the identified service and usage pattern.

### Phase 3 — Mitigation Recommendations
For each attack vector, recommend mitigations (controls, configurations, contractual requirements).

### Phase 4 — Lifecycle Management
Persist assessments to a local database. Track FQDNs with their vectors, mitigations, and implementation status. Periodically re-run risk estimation and notify if the score changes.

### Phase 5 — Cloud Automation
Automate management of firewall rules and security group egress rules across AWS and GCP based on the risk database.

---

## MVP Architecture

```
isrm/
  __init__.py
  cli.py                  # Click CLI:  isrm assess <target>
  config.py               # Pydantic Settings, loads from .env
  models.py               # AssessmentTarget, CollectedData, RiskReport, RiskLevel
  assess/
    __init__.py
    pipeline.py           # Orchestrates: collectors → agent → scorer → report
    collectors/
      __init__.py
      dns.py              # A/AAAA/MX/TXT/NS via dnspython
      whois.py            # Registration data via python-whois
      tls.py              # TLS cert inspection via ssl + cryptography
      http.py             # HTTP headers, redirects, tech fingerprint via httpx
      threat_intel.py     # VirusTotal v3 API
    agent.py              # Claude-powered agentic research (vendor, data types, known issues)
    scorer.py             # Weighted signal aggregation → score + rationale
    report.py             # Rich terminal output + optional JSON
tests/
  test_models.py
docs/
  product.md              # This file
  risk-estimation.md      # Risk scoring business logic
  python-practices.md     # Python coding standards
```

---

## CLI Interface

```bash
# Basic assessment
isrm assess api.stripe.com

# Output as JSON
isrm assess https://api.stripe.com/v1/charges --json

# Save report to file
isrm assess api.unknown-vendor.io --output report.json

# Verbose / debug logging
isrm assess api.example.com -v
```

The terminal output includes:
- Summary panel: target, resolved IPs, TLS grade, risk level + score
- Findings table: signal | observed value | score contribution | data status
- Agent findings: vendor identity, data types handled, known issues
- Risk verdict: numeric score, label, and rationale

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `httpx` | HTTP requests (collectors + threat intel) |
| `dnspython` | DNS record lookups |
| `python-whois` | WHOIS registration data |
| `cryptography` | TLS certificate parsing |
| `anthropic` | Claude SDK for agentic enrichment |
| `pydantic` | Data models |
| `pydantic-settings` | Config from env vars |
| `rich` | Terminal output formatting |
| `python-dotenv` | `.env` file support |

Dev: `pytest`, `ruff`, `mypy`

Package manager: **uv**

---

## Required Environment Variables

```
ANTHROPIC_API_KEY=...
VIRUSTOTAL_API_KEY=...   # Optional; missing key triggers DATA_UNAVAILABLE penalty
```

See `.env.example` for the full list.
