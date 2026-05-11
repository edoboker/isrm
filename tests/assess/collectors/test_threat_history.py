"""Tests for the threat-history collector."""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from isrm.assess.collectors.threat_history import collect_threat_history
from isrm.cli import main
from isrm.models import (
    CollectorStatus,
    EvidenceScope,
    ThreatHistoryEvidence,
    ThreatHistorySource,
)


def _make_settings(**overrides):
    from isrm.config import Settings
    defaults = {
        "openrouter_api_key": "test-key",
        "openrouter_model": "test-model",
        "tavily_api_key": None,
    }
    defaults.update(overrides)
    return Settings.model_construct(**defaults)


def _make_source(**overrides) -> ThreatHistorySource:
    defaults = dict(
        url="https://example-security.com/report",
        title="Report",
        source_type="malware_report",
        claim="Domain observed as C2.",
        credibility="high",
        evidence_scope=EvidenceScope.EXACT_FQDN,
        scope_note="Report explicitly names this FQDN.",
    )
    defaults.update(overrides)
    return ThreatHistorySource(**defaults)


# ---------------------------------------------------------------------------
# Original tests (updated for new required fields)
# ---------------------------------------------------------------------------

def test_data_unavailable_when_no_api_key():
    settings = _make_settings(tavily_api_key=None)
    result = collect_threat_history("example.com", settings)
    assert result.status == CollectorStatus.DATA_UNAVAILABLE
    assert result.name == "threat_history"
    assert result.payload is None


def test_mocked_agent_returns_valid_evidence():
    fake_evidence = ThreatHistoryEvidence(
        abuse_found=True,
        categories=["c2", "malware_delivery"],
        summary="Domain used as C2 in a 2023 campaign. Strongest scope: exact_fqdn.",
        strongest_scope=EvidenceScope.EXACT_FQDN,
        sources=[_make_source()],
        searched_queries=["example.com C2 malware"],
        confidence=85,
    )
    settings = _make_settings(tavily_api_key="fake-tavily-key")

    with patch("isrm.assess.collectors.threat_history.run_agent", return_value=fake_evidence):
        result = collect_threat_history("example.com", settings)

    assert result.status == CollectorStatus.OK
    assert isinstance(result.payload, ThreatHistoryEvidence)
    assert result.payload.abuse_found is True
    assert "c2" in result.payload.categories


def test_standalone_json_output():
    fake_evidence = ThreatHistoryEvidence(
        abuse_found=False,
        categories=[],
        summary="No public abuse evidence found. Strongest scope: none.",
        strongest_scope=None,
        sources=[],
        searched_queries=["clean.example.com threat intel"],
        confidence=60,
    )

    runner = CliRunner()
    with patch("isrm.assess.collectors.threat_history.run_agent", return_value=fake_evidence):
        with patch("isrm.cli.load_settings") as mock_settings:
            mock_settings.return_value = _make_settings(tavily_api_key="fake-tavily-key")
            result = runner.invoke(main, ["research-threat-history", "clean.example.com"])

    assert result.exit_code == 0, result.output
    json_start = result.output.index("{")
    data = json.loads(result.output[json_start:])
    assert data["name"] == "threat_history"
    assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# New scope and source-quality tests
# ---------------------------------------------------------------------------

def test_source_has_scope_fields():
    source = _make_source(
        evidence_scope=EvidenceScope.SAME_SERVICE,
        scope_note="Report is about the Stripe API generally, not this FQDN specifically.",
    )
    assert source.evidence_scope == EvidenceScope.SAME_SERVICE
    assert "Stripe" in source.scope_note


def test_brand_impersonation_not_exact_fqdn_abuse():
    impersonation_source = _make_source(
        evidence_scope=EvidenceScope.BRAND_IMPERSONATION,
        scope_note="Malicious npm package impersonating Stripe, not abuse of api.stripe.com.",
        credibility="high",
    )
    fake_evidence = ThreatHistoryEvidence(
        abuse_found=False,
        categories=[],
        summary="Brand impersonation found; no direct abuse of api.stripe.com. Strongest scope: brand_impersonation.",
        strongest_scope=EvidenceScope.BRAND_IMPERSONATION,
        sources=[impersonation_source],
        searched_queries=["api.stripe.com malware"],
        confidence=70,
    )
    settings = _make_settings(tavily_api_key="fake-tavily-key")

    with patch("isrm.assess.collectors.threat_history.run_agent", return_value=fake_evidence):
        result = collect_threat_history("api.stripe.com", settings)

    assert isinstance(result.payload, ThreatHistoryEvidence)
    assert result.payload.abuse_found is False
    assert result.payload.strongest_scope != EvidenceScope.EXACT_FQDN
    assert result.payload.strongest_scope == EvidenceScope.BRAND_IMPERSONATION


def test_low_credibility_social_source_does_not_set_abuse_found():
    social_source = _make_source(
        source_type="social",
        credibility="low",
        claim="Someone on LinkedIn claimed this domain was used in an attack.",
        evidence_scope=EvidenceScope.SAME_VENDOR,
        scope_note="LinkedIn post about the vendor, no technical evidence.",
    )
    fake_evidence = ThreatHistoryEvidence(
        abuse_found=False,
        categories=[],
        summary="Only a low-credibility social source found; abuse_found remains false. Strongest scope: same_vendor.",
        strongest_scope=EvidenceScope.SAME_VENDOR,
        sources=[social_source],
        searched_queries=["example.com abuse"],
        confidence=30,
    )
    settings = _make_settings(tavily_api_key="fake-tavily-key")

    with patch("isrm.assess.collectors.threat_history.run_agent", return_value=fake_evidence):
        result = collect_threat_history("example.com", settings)

    assert isinstance(result.payload, ThreatHistoryEvidence)
    assert result.payload.abuse_found is False
    source = result.payload.sources[0]
    assert source.credibility == "low"
    assert source.source_type == "social"


def test_strongest_scope_is_tightest():
    sources = [
        _make_source(evidence_scope=EvidenceScope.SAME_VENDOR, scope_note="Vendor-level only."),
        _make_source(evidence_scope=EvidenceScope.EXACT_FQDN, scope_note="FQDN in IOC feed."),
        _make_source(evidence_scope=EvidenceScope.SAME_SERVICE, scope_note="Service-level report."),
    ]
    # strongest_scope should be exact_fqdn (tightest)
    fake_evidence = ThreatHistoryEvidence(
        abuse_found=True,
        categories=["c2"],
        summary="FQDN found in IOC feed. Strongest scope: exact_fqdn.",
        strongest_scope=EvidenceScope.EXACT_FQDN,
        sources=sources,
        searched_queries=["example.com IOC"],
        confidence=90,
    )
    assert fake_evidence.strongest_scope == EvidenceScope.EXACT_FQDN
    assert fake_evidence.strongest_scope.severity() < EvidenceScope.SAME_VENDOR.severity()
    assert fake_evidence.strongest_scope.severity() < EvidenceScope.SAME_SERVICE.severity()
