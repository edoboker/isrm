# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**isrm** — internet service risk manager. Python CLI for CISOs to assess the risk of opening AWS/GCP VPCs to external FQDNs, services, and third parties.

## Load Context Only When Needed

- Before editing Python code, read `docs/python-practices.md`.
- Before changing scoring, risk dimensions, findings, labels, missing-data behavior, or report schema, read `docs/risk-estimation.md`.
- Before changing CLI behavior, dependencies, package layout, or roadmap behavior, read `docs/product.md`.


## Architecture Summary

The assessment pipeline flows: `collectors → agent → scorer → report`.

- `isrm/assess/collectors/` — independent data collectors (DNS, WHOIS, TLS, HTTP, threat intel)
- `isrm/assess/agent.py` — Claude SDK agentic enrichment (vendor research, data types, known issues)
- `isrm/assess/scorer.py` — aggregates signals into a 0–100 composite score across 5 weighted dimensions
- `isrm/assess/report.py` — Rich terminal output and JSON serialization
- `isrm/models.py` — Pydantic v2 models shared across modules
- `isrm/config.py` — Pydantic Settings loaded from env / `.env`

# General rules
1. Think Before Coding
Don't assume. Don't hide confusion. Surface tradeoffs.
2. Simplicity First
Minimum code that solves the problem. Nothing speculative.
3. Surgical Changes
Touch only what you must. Clean up only your own mess.