# ISRM — Product Specification

## What it is

ISRM is a CLI tool for CISOs and security architects to assess the risk of allowing cloud workloads to communicate with external FQDNs, SaaS services, APIs, and third parties.

## Core Problem

Cloud environments often need outbound access to external services, but security teams lack a repeatable way to answer:

- Who owns this endpoint?
- Is it reputable?
- What data might flow to or from it?
- Could it deliver executable or dangerous content?
- Is the infrastructure posture acceptable?
- What is the residual risk of allowing access?

## Product Principle

ISRM is an evidence-based risk assessment tool.

Collectors gather evidence.  
A judge interprets evidence and generates a structured report.  
Reports must be structured, auditable, and explainable.

## Architecture Principle

The system has four major phases:

CLI → pipeline → collectors → judge

- CLI handles user input and output mode.
- Pipeline orchestrates assessment execution.
- Collectors gather deterministic or agentic evidence.
- Judge uses an LLM to convert heterogeneous evidence into a structured risk report.

## Roadmap

### Phase 1 — Risk Estimation

Given a URL (with scheme, e.g. `https://api.example.com`), produce a structured risk assessment from collected evidence.

Phase 1a (current):
- TLS/certificate posture
- Threat reputation via VirusTotal
- HTTP posture (headers, redirects)
- LLM judge (OpenRouter) producing a structured score and rationale

Phase 1b (later):
- Support bare FQDN input without scheme
- Additional collectors (DNS, WHOIS, agentic vendor research)

### Phase 2 — Attack Vectors

For each risk finding, generate relevant threat scenarios.

### Phase 3 — Mitigation Recommendations

For each attack vector, recommend controls, configurations, and compensating measures.

### Phase 4 — Lifecycle Management

Persist assessments, track changes over time, and periodically re-assess known FQDNs.

### Phase 5 — Cloud Automation

Use the risk database to help manage cloud egress controls across AWS/GCP.