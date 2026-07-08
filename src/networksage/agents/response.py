"""Response Agent."""

from __future__ import annotations

import time
from typing import Iterable

from networksage.schemas.models import (
    AttributionRef,
    EnrichmentResult,
    InvestigationResult,
    PipelineState,
    RecommendedAction,
    ResponseResult,
    TriageResult,
)


_ACTION_BY_CATEGORY = {
    "phishing": [("quarantine_email", "user mailbox", 0.85, False), ("block_sender_domain", "sender_domain", 0.9, False), ("alert_user", "user", 0.95, True)],
    "malware": [("isolate_host", "host", 0.85, False), ("block_file_hash", "file_hash", 0.9, True), ("scan_endpoints", "host_subnet", 0.7, True)],
    "command_and_control": [("block_dst_ip", "dst_ip", 0.9, True), ("block_dst_domain", "dst_domain", 0.9, True), ("investigate_host", "host", 0.6, True)],
    "exfiltration": [("block_egress", "src_ip", 0.85, False), ("preserve_logs", "host", 0.95, True), ("escalate_ir", "incident", 0.9, False)],
    "lateral_movement": [("isolate_host", "host", 0.85, False), ("rotate_credentials", "user", 0.8, False), ("review_vpn_logs", "vpn_gateway", 0.7, True)],
    "initial_access": [("block_src_ip", "src_ip", 0.85, True), ("patch_application", "vulnerable_service", 0.7, False), ("review_auth_logs", "auth_log_source", 0.7, True)],
    "privilege_escalation": [("rotate_credentials", "user", 0.8, False), ("audit_admin_groups", "directory", 0.7, True), ("escalate_ir", "incident", 0.85, False)],
    "reconnaissance": [("rate_limit_src", "src_ip", 0.7, True), ("monitor_src", "src_ip", 0.8, True)],
    "impact": [("isolate_host", "host", 0.95, False), ("escalate_ir", "incident", 0.95, False), ("preserve_forensics", "host", 0.9, False)],
    "unknown": [("enrich_alert", "alert", 0.5, True), ("manual_review", "alert", 0.9, False)],
}


def _resolve_target(field_hint: str, triage: TriageResult, enrichment: EnrichmentResult) -> str | None:
    def _first_indicator(kind: str) -> str | None:
        for i in triage.indicators:
            if i.type.value == kind:
                return i.value
        return None

    if field_hint == "src_ip":
        return _first_indicator("ipv4") or "src_ip"
    if field_hint == "dst_ip":
        for i in triage.indicators:
            if i.type.value != "ipv4":
                continue
            verdict = enrichment.enriched_indicators.get(i.value, {}).get("verdicts", {}).get("abuseipdb", {}).get("verdict")
            if verdict in {"malicious", "suspicious"}:
                return i.value
        return _first_indicator("ipv4")
    if field_hint in {"dst_domain", "sender_domain"}:
        return _first_indicator("domain")
    if field_hint == "file_hash":
        return _first_indicator("sha256") or _first_indicator("sha1") or _first_indicator("md5")
    return field_hint


def _recommend_actions(triage: TriageResult, enrichment: EnrichmentResult) -> list[RecommendedAction]:
    actions = _ACTION_BY_CATEGORY.get(triage.category.value, _ACTION_BY_CATEGORY["unknown"])
    out: list[RecommendedAction] = []
    for verb, target_field, confidence, automation_safe in actions:
        target = _resolve_target(target_field, triage, enrichment)
        if target is None:
            continue
        out.append(RecommendedAction(action=verb, target=target, rationale=f"Recommended by Response Agent for {triage.category.value} alert with severity {triage.severity.value}.", confidence=confidence, automation_safe=automation_safe))
    if not out:
        out.append(RecommendedAction(action="manual_review", target="alert", rationale="No automated recommendations available. Escalate to Tier-2 analyst.", confidence=0.9, automation_safe=False))
    return out


def _executive_summary(state: PipelineState) -> str:
    triage = state.triage
    inv = state.investigation
    if triage is None or inv is None:
        return "Investigation incomplete."
    top_tech = inv.mitre_techniques[0] if inv.mitre_techniques else {"id": "unknown", "title": "unmapped"}
    ioc_count = len(triage.indicators)
    malicious = sum(1 for h in (state.enrichment.hits if state.enrichment else []) if h.verdict == "malicious")
    return (
        f"A {triage.severity.value}-severity {triage.category.value} alert was triaged by NetworkSage-X. "
        f"{ioc_count} indicators of compromise were extracted and {malicious} returned malicious verdicts "
        f"from threat intel providers. The investigation mapped the activity to MITRE technique "
        f"{top_tech['id']} ({top_tech['title']}). Recommended actions are listed below; "
        f"auto-executable actions are marked."
    )


def _detailed_findings(state: PipelineState) -> str:
    triage = state.triage
    inv = state.investigation
    if triage is None or inv is None:
        return ""
    parts: list[str] = []
    parts.append(f"Alert: {state.alert.title}")
    if state.alert.description:
        parts.append(f"Description: {state.alert.description}")
    parts.append(f"Category: {triage.category.value} (confidence {triage.category_confidence:.2f})")
    parts.append(f"Severity: {triage.severity.value} (confidence {triage.severity_confidence:.2f})")
    if triage.indicators:
        parts.append("Indicators extracted:")
        for i in triage.indicators[:10]:
            parts.append(f"  - {i.type.value}: {i.value} (conf {i.confidence:.2f})")
    if state.enrichment and state.enrichment.hits:
        parts.append("Threat intel verdicts:")
        for h in state.enrichment.hits[:10]:
            parts.append(f"  - {h.provider} on {h.indicator}: {h.verdict} (score={h.score})")
    if inv.mitre_techniques:
        parts.append("MITRE ATT&CK mapping:")
        for t in inv.mitre_techniques:
            parts.append(f"  - {t['id']}: {t['title']} (score {t['score']:.2f})")
    if inv.cves:
        parts.append("CVE references:")
        for c in inv.cves:
            parts.append(f"  - {c['id']}: {c['title']}")
    parts.append(f"Rationale: {triage.rationale}")
    return "\n".join(parts)


def _markdown_report(state: PipelineState, summary: str, findings: str, actions: Iterable[RecommendedAction]) -> str:
    lines: list[str] = []
    lines.append(f"# Incident Report: {state.alert.alert_id}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(summary)
    lines.append("")
    lines.append("## Detailed Findings")
    lines.append("```")
    lines.append(findings)
    lines.append("```")
    lines.append("")
    lines.append("## Recommended Actions")
    for a in actions:
        auto = "auto" if a.automation_safe else "manual"
        lines.append(f"- **{a.action}** on `{a.target}` [{auto}, conf {a.confidence:.2f}]  -  {a.rationale}")
    lines.append("")
    lines.append("## Attribution Chain")
    for ref in state.all_attribution()[:20]:
        weight = f" (weight {ref.weight:.2f})" if ref.weight != 1.0 else ""
        snippet = f": {ref.snippet}" if ref.snippet else ""
        lines.append(f"- [{ref.kind}] {ref.ref_id}{weight}{snippet}")
    return "\n".join(lines)


def draft_response(state: PipelineState) -> ResponseResult:
    start = time.perf_counter()
    triage = state.triage
    enrichment = state.enrichment
    investigation = state.investigation
    if triage is None or enrichment is None or investigation is None:
        raise ValueError("Cannot draft response: upstream agents have not completed.")
    actions = _recommend_actions(triage, enrichment)
    summary = _executive_summary(state)
    findings = _detailed_findings(state)
    report_md = _markdown_report(state, summary, findings, actions)
    citations: list[AttributionRef] = [AttributionRef(kind="rule_match", ref_id=f"action:{a.action}", snippet=f"Target {a.target}", weight=a.confidence) for a in actions]
    full_attribution = state.all_attribution() + citations
    latency_ms = int((time.perf_counter() - start) * 1000)
    return ResponseResult(
        executive_summary=summary,
        detailed_findings=findings,
        recommended_actions=actions,
        citations=citations,
        full_attribution_chain=full_attribution,
        report_markdown=report_md,
        latency_ms=latency_ms,
    )