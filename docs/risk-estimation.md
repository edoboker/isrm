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
| `threat_history` | Public abuse history via agentic web research (Pydantic AI + Tavily) |

Each collector returns a status (`ok`, `partial`, `failed`, `data_unavailable`) and a summary. A dedicated evaluator converts each collector result into an `EvaluatedFinding` (score 0–100). The judge synthesizes all findings into the composite report.

### Threat-history collector

The `threat_history` collector runs an LLM agent that searches the web from narrowest to broadest scope (exact FQDN → service → vendor). Every source is tagged with an `evidence_scope` value. The evaluator scores by the tightest credible scope found:

| Tightest scope | Score range |
|----------------|-------------|
| `exact_url` / `exact_fqdn` | 75–90 |
| `same_route_or_api` | 55–74 |
| `same_service` | 30–54 |
| `same_vendor` | 15–29 |
| `brand_impersonation` | 5–14 |
| No abuse found | 0–10 |

---

## Missing Data Policy

Missing data is handled inside each collector's finding — not as a separate dimension.

- If a collector status is `failed` or `data_unavailable`, the judge scores that finding as elevated risk and sets `data_gap: true`.
- The reason (e.g. "VIRUSTOTAL_API_KEY not set") appears in the finding's explanation and in the report's `data_gaps` list.

Future phases will allow manual overrides per flagged collector (e.g. a CISO supplying vendor details after a meeting).

---

## Scoring Model

- Each collector result is scored 0–100 by its dedicated evaluator. The evaluator uses a focused LLM prompt with domain-specific scoring bands.
- The judge receives pre-scored `EvaluatedFinding` objects and synthesizes them into a composite `score` (0–100). It considers interactions between findings (e.g. confirmed threat history amplifies infrastructure weaknesses) but does not re-score individual collectors.
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
  findings: list[EvaluatedFinding]
    EvaluatedFinding
      collector: str            # collector name, e.g. "tls"
      score: int                # 0–100, set by the per-collector evaluator
      explanation: str
      data_gap: bool
      confidence: int           # 0–100
  rationale: str
  assumptions: list[str]
  data_gaps: list[str]
  confidence: int               # 0–100
```
