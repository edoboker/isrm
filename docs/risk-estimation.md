# Risk Estimation — Business Logic

## Overview

Given a FQDN or URL, isrm produces a risk score by collecting signals across five dimensions, enriching them with agentic research, and aggregating them into a composite score.

---

## Risk Dimensions

### 1. Threat Reputation (weight: 30%)
Measures whether the domain/IP is associated with known malicious activity.

Signals:
- VirusTotal community score (malicious/suspicious/harmless votes)
- Domain categorization (malware, phishing, botnet C2, etc.)
- Domain age (newly registered domains carry higher risk)
- Historical incidents or blacklist appearances

### 2. Vendor / Service Profile (weight: 25%)
Measures how well-known, audited, and trustworthy the service provider is.

Signals:
- Vendor identity (well-known SaaS vs. unknown entity)
- Industry sector and typical customers
- Security certifications (SOC 2 Type II, ISO 27001, FedRAMP, etc.)
- Known data breaches or CVEs affecting the service
- Privacy policy and data retention practices

### 3. Data Sensitivity Exposure (weight: 20%)
Measures the sensitivity of data that flows to/from this endpoint.

Signals:
- Data types handled: PII, financial data, credentials, health data, secrets
- Whether the service stores or merely processes data in transit
- Regulatory scope (GDPR, HIPAA, PCI-DSS applicability)

### 4. Usage Pattern / Data Flow (weight: 15%)
Measures the inherent risk introduced by how your systems interact with this endpoint.

Signals:
- **Inbound executable content** (packages, binaries, code, configs): high risk — a compromised or malicious endpoint could deliver malware that executes in your environment.
- **Inbound structured data** (JSON/XML APIs, database records): medium risk — malformed data could trigger parsing vulnerabilities or data poisoning.
- **Outbound-only data push** (telemetry, logs, metrics): lower risk — no execution surface, limited inbound attack vector.
- **Bidirectional / interactive** (e.g., auth providers, streaming APIs): medium risk, depends on data types.

### 5. Infrastructure Posture (weight: 10%)
Measures the security hygiene of the endpoint's infrastructure.

Signals:
- TLS version and cipher suite strength (graded A–F)
- Certificate validity (expiry, issuer trust, SANs)
- DNSSEC presence
- HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- Hosting provider reputation (cloud, CDN, or known bulletproof hosting)

---

## Scoring Model

### Dimension scores
Each dimension is scored on a scale of **0–100**, where 0 = no risk and 100 = maximum risk.

Scoring within each dimension is performed by the scorer module using a defined signal-to-score mapping. The Claude agent provides structured findings that feed into this mapping.

### Composite score
```
composite = sum(dimension_score[i] * weight[i]  for i in dimensions)
```

### Risk label
| Score range | Label    |
|-------------|----------|
| 0 – 25      | Low      |
| 26 – 50     | Medium   |
| 51 – 75     | High     |
| 76 – 100    | Critical |

### Default weights
Weights are configurable in `config.py`. Defaults:

```python
DIMENSION_WEIGHTS = {
    "threat_reputation":     0.30,
    "vendor_profile":        0.25,
    "data_sensitivity":      0.20,
    "usage_pattern":         0.15,
    "infrastructure_posture": 0.10,
}
```

---

## Missing Information Policy

Any signal or dimension that cannot be assessed due to missing data (API key not configured, vendor not found, host unreachable, no documentation available, etc.) is handled as follows:

1. **Penalize**: The dimension or signal defaults to a penalty score (default: **70/100** for the dimension). This is configurable.
2. **Flag**: The finding is tagged `DATA_UNAVAILABLE` with a specific reason string (e.g., `"VirusTotal API key not configured"`, `"No vendor documentation found"`).
3. **Surface**: Every `DATA_UNAVAILABLE` flag appears in the report so the analyst knows exactly what was assumed and why.

This applies to **all** data gaps — not just vendor information. Examples:
- VirusTotal key absent → threat_reputation dimension flagged
- TLS connection refused → infrastructure_posture dimension flagged
- Claude agent finds no documentation → data_sensitivity and usage_pattern flagged
- WHOIS returns no registration data → domain age signal flagged

### Future: manual overrides
Phase 4 will introduce a mechanism to supply manual data for any flagged signal (e.g., CISO enters vendor cert details after a vendor meeting), replacing the penalty score with an analyst-provided value and recording the override source and date.

---

## Output: Risk Rationale

Every assessment report includes a structured rationale:

```
RiskReport
  target: str
  composite_score: int          # 0–100
  risk_label: RiskLevel         # Low / Medium / High / Critical
  dimensions: list[DimensionResult]
    DimensionResult
      name: str
      weight: float
      score: int
      findings: list[Finding]
        Finding
          signal: str
          observed_value: str | None
          score_contribution: int
          data_unavailable: bool
          unavailability_reason: str | None
```

This structure ensures every score is fully explainable and auditable.
