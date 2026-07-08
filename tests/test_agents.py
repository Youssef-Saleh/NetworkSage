"""End-to-end pipeline smoke test."""

from networksage.agents.graph import run_alert
from networksage.clients.hf_client import HFClient
from networksage.schemas.models import (
    AlertSource,
    NetworkAlert,
    Severity,
    AttackCategory,
)


def test_pipeline_smoke_phishing() -> None:
    """Phishing alert with IOC + CVE should produce a full report."""
    alert = NetworkAlert(
        alert_id="SMOKE-PHISH-001",
        source=AlertSource.SURICATA,
        title="Suspicious email with CVE-2024-1234 from attacker@evil.example",
        description=(
            "Email from attacker@evil.example with attachment exploiting "
            "CVE-2024-1234. Hash: "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        destination_domain="evil.example",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    state = run_alert(alert, HFClient())
    assert state.triage is not None
    assert state.enrichment is not None
    assert state.investigation is not None
    assert state.response is not None
    assert state.response.report_markdown
    assert "Incident Report" in state.response.report_markdown
    assert len(state.all_attribution()) > 0


def test_pipeline_smoke_recon() -> None:
    """Port scan should produce a triage result with the right category."""
    alert = NetworkAlert(
        alert_id="SMOKE-RECON-001",
        source=AlertSource.SURICATA,
        title="External port scan from 203.0.113.7",
        description="Source IP 203.0.113.7 performed a TCP SYN scan.",
        src_ip="203.0.113.7",
    )
    state = run_alert(alert, HFClient())
    assert state.triage is not None
    assert state.triage.category in (AttackCategory.RECONNAISSANCE, AttackCategory.UNKNOWN)