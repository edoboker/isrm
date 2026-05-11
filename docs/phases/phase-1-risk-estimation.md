# Phase 1 — Risk Estimation Implementation Spec

## Purpose

Implement the first working version of ISRM risk estimation.

Given a URL, ISRM should collect evidence about the target and produce a structured, explainable risk report.

Note: bare FQDN input (without scheme) is not supported in Phase 1. The target must be a URL with a scheme, e.g. `https://api.example.com`.

This phase implements the core product loop:

```text
CLI → pipeline → collectors → judge → report
```

## Product Context

ISRM is an evidence-based risk assessment CLI for CISOs and security architects evaluating whether cloud workloads should be allowed to communicate with external FQDNs, SaaS services, APIs, and third parties.

Phase 1 focuses only on risk estimation. Do not implement attack vectors, mitigation recommendations, persistence, scheduled re-assessment, or cloud firewall automation.

## Scope

### In scope

Implement a working CLI command:

```bash
isrm assess <target>
```

Where `<target>` must be a URL with a scheme:

```text
https://api.example.com/path
```

Bare FQDNs without a scheme (e.g. `api.example.com`) are not supported in Phase 1.

The command should:

1. Normalize the input target.
2. Run initial collectors.
3. Bundle collector evidence.
4. Send evidence to an LLM judge.
5. Validate the judge output into a structured Pydantic model.
6. Render a human-readable terminal report.
7. Support JSON output.

### Initial collectors

Implement these collectors first:

1. TLS / certificate collector
2. VirusTotal reputation collector
3. Basic HTTP collector

The architecture must allow more collectors later, including agentic collectors that return long-form textual evidence.

### Out of scope

Do not implement:

- attack vector generation
- mitigation generation
- database persistence
- periodic re-assessment
- cloud firewall/security-group automation
- a web UI
- complex plugin frameworks
- async execution unless it is clearly simpler for the chosen HTTP client
- broad dependency injection frameworks
- premature abstractions such as hexagonal architecture scaffolding

## Architecture

Use this architecture:

```text
cli.py
  ↓
pipeline.py
  ↓
collectors/*
  ↓
judge.py
  ↓
report.py
```

### CLI responsibilities

The CLI should be thin.

It should:

- parse arguments
- load settings
- call the pipeline
- choose terminal output or JSON output
- handle top-level user-facing errors

It should not:

- call collectors directly
- contain scoring logic
- contain LLM prompt logic
- know collector-specific details

### Pipeline responsibilities

The pipeline orchestrates the assessment.

It should:

- normalize the target into an `AssessmentTarget`
- run collectors
- collect their outputs into an `EvidenceBundle`
- call the judge
- return a `RiskReport`

The pipeline should not make final risk decisions itself.

### Collector responsibilities

Collectors gather evidence. They do not assign final risk scores.

Each collector should return a typed collector result with:

- collector name
- status
- short summary
- typed payload where available
- optional raw text evidence
- errors or unavailable-data reasons

Collectors may be deterministic or agentic in the future.

For Phase 1, deterministic collectors are enough, but the collector model must support long textual evidence because future collectors may produce research summaries.

### Judge responsibilities

The judge interprets heterogeneous evidence and produces the final structured risk report.

The judge may use an LLM, but the output must be schema-valid and parsed into Pydantic models.

The judge should:

- read all collector evidence
- identify missing or unreliable data
- estimate risk conservatively
- produce a numeric score
- produce a risk label
- explain the rationale
- separate facts from assumptions
- emit structured output only

The judge must not return only free-form Markdown.

## Data Model Requirements

Use Pydantic v2 models for data crossing module boundaries.

Do not return raw dictionaries from public module APIs.

Recommended core models:

```text
AssessmentTarget
EvidenceBundle
CollectorResult
CollectorStatus
TLSEvidence
VirusTotalEvidence
HTTPEvidence
JudgeFinding
RiskReport
RiskLabel
```

### AssessmentTarget

Represents the normalized user input.

Should include:

- original input
- normalized hostname
- normalized URL if applicable
- scheme, defaulting to `https` when needed

### CollectorStatus

Use explicit statuses:

```text
ok
partial
failed
data_unavailable
```

### CollectorResult

A generic wrapper around collector evidence.

Should include:

- collector name
- status
- summary
- payload
- raw text, optional
- errors, optional

The payload should be typed. Avoid `dict[str, Any]` unless there is no better option.

### EvidenceBundle

Contains:

- assessment target
- list of collector results

### RiskReport

The judge output.

Should include:

- target
- composite score from 0 to 100
- risk label
- findings
- rationale
- assumptions
- data gaps
- confidence

## Initial Collector Behavior

### TLS collector

Given a hostname, collect certificate and TLS posture evidence.

Useful facts:

- whether TLS connection succeeded
- certificate subject
- certificate issuer
- certificate validity period
- whether certificate is expired
- whether hostname matches certificate
- whether the chain is trusted by the local trust store
- negotiated TLS version, if available
- failure reason, if unavailable

The collector should not decide final risk.

Example summary:

```text
TLS certificate exists, is currently valid, chains to a trusted CA, and matches the requested hostname.
```

### VirusTotal collector

Given a hostname, query VirusTotal if an API key is configured.

Useful facts:

- malicious count
- suspicious count
- harmless count
- undetected count
- reputation score if available
- last analysis date if available
- categories if available

If `VIRUSTOTAL_API_KEY` is missing, return `data_unavailable`, not success.

Missing VirusTotal data must be visible to the judge.

### HTTP collector

Given a URL or hostname, perform a basic HTTP request.

Useful facts:

- final URL after redirects
- status code
- whether HTTPS was used
- redirect chain
- selected security headers, if present:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
- server header, if present
- content type, if present

Do not over-invest in fingerprinting in Phase 1.

## LLM Judge Contract

The LLM judge receives the `EvidenceBundle` and returns a `RiskReport`.

The prompt should instruct the judge to behave as a security risk assessor for external FQDN access from cloud workloads.

The judge should evaluate at least these dimensions:

1. Threat reputation
2. Vendor/service confidence
3. Data-flow and usage risk
4. Infrastructure posture
5. Missing-data risk

The judge may infer risk from textual evidence, but every inference must be explained.

The judge must treat missing data conservatively.

Required judge behavior:

- do not ignore failed collectors
- do not treat missing data as safe
- do not invent facts not present in evidence
- distinguish observed facts from assumptions
- produce valid structured output
- keep rationale concise but auditable

## Scoring Guidance

Use a 0–100 risk score:

```text
0   = no meaningful risk identified
100 = maximum risk / unacceptable risk
```

Risk labels:

```text
0–25    Low
26–50   Medium
51–75   High
76–100  Critical
```

The exact scoring is judgment-based in Phase 1, but the judge must explain why the selected score follows from the evidence.

Missing critical evidence should increase risk or reduce confidence.

## Configuration

Use Pydantic Settings.

Environment variables:

```text
OPENROUTER_API_KEY
OPENROUTER_MODEL      (optional, default: anthropic/claude-3.5-sonnet)
VIRUSTOTAL_API_KEY
```

`VIRUSTOTAL_API_KEY` may be optional. If absent, the VirusTotal collector returns `data_unavailable`.

`OPENROUTER_API_KEY` is required for the LLM judge. The judge uses the OpenAI-compatible OpenRouter API (`https://openrouter.ai/api/v1`).

## Output Requirements

### Terminal output

Human-readable terminal output should show:

- target
- composite risk score
- risk label
- short rationale
- collector statuses
- key findings
- data gaps
- assumptions

### JSON output

Support:

```bash
isrm assess <target> --json
```

JSON output should serialize the `RiskReport` model.

## Testing Requirements

Implement tests for:

- target normalization
- Pydantic model validation
- TLS collector behavior with mocked network calls where practical
- VirusTotal collector behavior when API key is missing
- HTTP collector behavior with mocked responses
- pipeline orchestration using fake collectors and fake judge
- JSON serialization of `RiskReport`

Do not require real external network calls in unit tests.

If integration tests are added, mark them separately so normal test runs do not depend on internet access or paid APIs.

## Error Handling

Failures should be represented as evidence when possible.

Examples:

- TLS handshake failed → collector result with `failed`
- VirusTotal key missing → collector result with `data_unavailable`
- HTTP timeout → collector result with `failed` or `partial`
- LLM judge response invalid → user-facing error and logged diagnostic context

Do not silently swallow errors.

Do not crash the entire assessment because one collector failed, unless the target itself cannot be normalized.

## Logging

Use Python `logging`.

Do not use `print` for operational output.

CLI user output should go through the report renderer.

## Implementation Order

Recommended order:

1. Create/adjust Pydantic models.
2. Implement target normalization.
3. Implement CLI skeleton.
4. Implement pipeline with fake collector and fake judge.
5. Implement report rendering and JSON output.
6. Implement TLS collector.
7. Implement VirusTotal collector.
8. Implement HTTP collector.
9. Implement real LLM judge.
10. Add tests and run lint/type checks.

## Acceptance Criteria

The following should work:

```bash
uv run isrm assess example.com
uv run isrm assess https://example.com --json
uv run pytest
uv run ruff check .
uv run mypy isrm/
```

A successful assessment should produce a structured report even when VirusTotal is unavailable.

The report must clearly show which evidence was collected, which evidence was unavailable, and how that affected the risk judgment.

## Non-Goals for Phase 1

Do not optimize for perfect scoring yet.

The main goal is a clean evidence-to-judgment architecture that can support more collectors and richer judge prompts later.
