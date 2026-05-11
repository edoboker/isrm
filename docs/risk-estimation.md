# Risk Estimation — Business Logic

## Overview

Given a URL, isrm runs a set of collectors, then passes all evidence to an LLM judge which produces a structured risk report. Findings map 1:1 to collectors — there are no synthetic dimensions beyond what collectors actually provide.

---

## Current Collectors (Phase 1)

| Collector | What it measures |
|-----------|-----------------|
| `tls` | Certificate validity, expiry, hostname match, chain trust, TLS version |
| `http` | HTTP posture: final URL, HTTPS enforcement, security headers |
| `virustotal` | Threat reputation: malicious/suspicious detections, reputation score |

Each collector returns a status (`ok`, `partial`, `failed`, `data_unavailable`) and a summary. The judge produces one finding per collector.

---

## Missing Data Policy

Missing data is handled inside each collector's finding — not as a separate dimension.

- If a collector status is `failed` or `data_unavailable`, the judge scores that finding as elevated risk and sets `data_gap: true`.
- The reason (e.g. "VIRUSTOTAL_API_KEY not set") appears in the finding's explanation and in the report's `data_gaps` list.

Future phases will allow manual overrides per flagged collector (e.g. a CISO supplying vendor details after a meeting).

---

## Scoring Model

- Each finding has a `score_contribution` (0–100).
- The judge produces an overall composite `score` (0–100) based on its reading of all findings.
- Weighting logic lives in the judge prompt and may be refined over time.

### Risk label

| Score range | Label    |
|-------------|----------|
| 0 – 25      | Low      |
| 26 – 50     | Medium   |
| 51 – 75     | High     |
| 76 – 100    | Critical |

---

## Future Dimensions

As new collectors are added (e.g. WHOIS, DNS, agentic vendor research), their findings will appear automatically — no schema change needed. Grouping findings into named categories (e.g. "infrastructure posture", "vendor profile") may be introduced in a later phase if the number of collectors grows enough to warrant it.

---

## Output Schema

```
RiskReport
  target: str
  score: int                    # 0–100 composite
  label: RiskLabel              # Low / Medium / High / Critical
  findings: list[JudgeFinding]
    JudgeFinding
      dimension: str            # collector name, e.g. "tls"
      score_contribution: int   # 0–100
      explanation: str
      data_gap: bool
  rationale: str
  assumptions: list[str]
  data_gaps: list[str]
  confidence: int               # 0–100
```
