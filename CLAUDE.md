# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**isrm** — internet service risk manager. Python CLI for CISOs to assess the risk of opening AWS/GCP VPCs to external FQDNs, services, and third parties.

## Load Context Only When Needed

- Before editing Python code, read `docs/python-practices.md`.
- Before changing scoring, risk dimensions, findings, labels, missing-data behavior, or report schema, read `docs/risk-estimation.md`.
- Before changing CLI behavior, dependencies, package layout, or roadmap behavior, read `docs/product.md`.


## Architecture Summary

The assessment pipeline flows: `collectors → evaluators → judge → report`.

- `isrm/assess/collectors/` — independent data collectors (TLS, HTTP, VirusTotal, threat_history)
- `isrm/assess/evaluators/` — one LLM evaluator per collector, produces `EvaluatedFinding` (score 0–100)
- `isrm/assess/judge.py` — LLM synthesizes `EvaluatedFinding` list into composite `RiskReport`
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
4. Git commits
Never add "Co-Authored-By: Claude" or any AI attribution to commit messages.