"""Triage Agent."""

from __future__ import annotations

import time

from networksage.clients.hf_client import HFClient
from networksage.clients.iocs import extract_indicators_from_alert
from networksage.schemas.models import (
    AttackCategory,
    AttributionRef,
    Indicator,
    IndicatorType,
    NetworkAlert,
    Severity,
    TriageResult,
)


_SEVERITY_LABELS = [s.value for s in Severity]
_CATEGORY_LABELS = [c.value for c in AttackCategory]


def _keyword_severity(text: str) -> tuple[Severity, float]:
    text_l = text.lower()
    if any(k in text_l for k in ("ransomware", "encrypt", "exfiltrat", "lateral movement", "privilege escalat", "pass-the-hash", "data encrypted")):
        return Severity.CRITICAL, 0.85
    if any(k in text_l for k in ("malware", "command and control", "phish", "dropper", "suspicious email")):
        return Severity.HIGH, 0.75
    if any(k in text_l for k in ("scan", "recon", "probe")):
        return Severity.MEDIUM, 0.6
    if any(k in text_l for k in ("informational", "policy", "usb")):
        return Severity.LOW, 0.7
    return Severity.INFO, 0.4


def _keyword_category(text: str) -> tuple[AttackCategory, float]:
    text_l = text.lower()
    if "ransomware" in text_l or "data encrypted" in text_l or "encryption detected" in text_l or "mass file encryption" in text_l:
        return AttackCategory.IMPACT, 0.85
    if "phish" in text_l or "suspicious email" in text_l or "spearphish" in text_l or ("email" in text_l and "cve-" in text_l and "attachment" in text_l):
        return AttackCategory.PHISHING, 0.8
    if "scan" in text_l or "port scan" in text_l or "syn scan" in text_l:
        return AttackCategory.RECONNAISSANCE, 0.7
    if "exfil" in text_l:
        return AttackCategory.EXFILTRATION, 0.8
    if "malware" in text_l or "powershell" in text_l or "dropper" in text_l:
        return AttackCategory.MALWARE, 0.75
    if "lateral movement" in text_l or "pass-the-hash" in text_l or "pass the hash" in text_l:
        return AttackCategory.LATERAL_MOVEMENT, 0.8
    if "command and control" in text_l or "beacon" in text_l or "periodic beacon" in text_l:
        return AttackCategory.COMMAND_AND_CONTROL, 0.85
    return AttackCategory.UNKNOWN, 0.4


def _candidate_techniques(category: AttackCategory, iocs_text: str) -> list[str]:
    text_l = iocs_text.lower()
    mapping: dict[AttackCategory, list[str]] = {
        AttackCategory.PHISHING: ["T1566", "T1078", "T1059", "T1190"],
        AttackCategory.MALWARE: ["T1059", "T1027", "T1053", "T1071"],
        AttackCategory.COMMAND_AND_CONTROL: ["T1071", "T1098", "T1059"],
        AttackCategory.EXFILTRATION: ["T1041", "T1071"],
        AttackCategory.LATERAL_MOVEMENT: ["T1078", "T1059", "T1098"],
        AttackCategory.PRIVILEGE_ESCALATION: ["T1078", "T1098"],
        AttackCategory.INITIAL_ACCESS: ["T1190", "T1566", "T1078"],
        AttackCategory.RECONNAISSANCE: ["T1071", "T1046"],
        AttackCategory.IMPACT: ["T1486", "T1041", "T1059.001", "T1566"],
        AttackCategory.UNKNOWN: [],
    }
    candidates = list(mapping.get(category, []))
    if "powershell" in text_l or ".ps1" in text_l or "encodedcommand" in text_l or "encoded command" in text_l:
        candidates.append("T1059.001")
    if "python" in text_l:
        candidates.append("T1059.006")
    if "cmd" in text_l or "command shell" in text_l:
        candidates.append("T1059.003")
    if "cve-" in text_l:
        candidates.append("T1190")
    if "encoded" in text_l or "obfuscat" in text_l:
        candidates.append("T1027")
    if "ntlm" in text_l or "pass-the-hash" in text_l or "pass the hash" in text_l:
        candidates.append("T1550.003")
    return sorted(set(candidates))


def triage_alert(alert: NetworkAlert, hf_client: HFClient) -> TriageResult:
    start = time.perf_counter()
    alert_dict = alert.model_dump()
    text_for_scoring = " ".join(str(v) for v in (alert.title, alert.description, alert.raw.get("signature", "")))

    try:
        scores = hf_client.zero_shot_classify(text=text_for_scoring, labels=_SEVERITY_LABELS)
        max_score = max(scores.values()) if scores else 0.0
        if max_score < 0.15:
            severity, severity_confidence = _keyword_severity(text_for_scoring)
        else:
            top = max(scores.items(), key=lambda kv: kv[1])
            severity = Severity(top[0])
            severity_confidence = float(top[1])
    except Exception:
        severity, severity_confidence = _keyword_severity(text_for_scoring)

    try:
        scores = hf_client.zero_shot_classify(text=text_for_scoring, labels=_CATEGORY_LABELS)
        max_score = max(scores.values()) if scores else 0.0
        if max_score < 0.15:
            category, category_confidence = _keyword_category(text_for_scoring)
        else:
            top = max(scores.items(), key=lambda kv: kv[1])
            category = AttackCategory(top[0])
            category_confidence = float(top[1])
    except Exception:
        category, category_confidence = _keyword_category(text_for_scoring)

    indicators = extract_indicators_from_alert(alert_dict, hf_client)

    if alert.src_ip and not any(i.value == alert.src_ip for i in indicators):
        indicators.append(Indicator(value=alert.src_ip, type=IndicatorType.IPV4, confidence=1.0))
    if alert.dst_ip and not any(i.value == alert.dst_ip for i in indicators):
        indicators.append(Indicator(value=alert.dst_ip, type=IndicatorType.IPV4, confidence=1.0))
    if alert.destination_domain and not any(i.value == alert.destination_domain for i in indicators):
        indicators.append(Indicator(value=alert.destination_domain, type=IndicatorType.DOMAIN, confidence=1.0))
    if alert.file_hash and not any(i.value.lower() == alert.file_hash.lower() for i in indicators):
        indicators.append(Indicator(value=alert.file_hash.lower(), type=IndicatorType.SHA256, confidence=1.0))
    if alert.url and not any(i.value == alert.url for i in indicators):
        indicators.append(Indicator(value=alert.url, type=IndicatorType.URL, confidence=1.0))

    iocs_text = " ".join([alert.title, alert.description] + [i.value for i in indicators])
    candidates = _candidate_techniques(category, iocs_text)

    attribution: list[AttributionRef] = []
    if alert.title:
        attribution.append(AttributionRef(kind="alert_field", ref_id="title", snippet=alert.title))
    if alert.description:
        attribution.append(AttributionRef(kind="alert_field", ref_id="description", snippet=alert.description[:200]))
    for ind in indicators:
        attribution.append(AttributionRef(kind="ioc", ref_id=ind.value, weight=ind.confidence))
    for tid in candidates:
        attribution.append(AttributionRef(kind="mitre", ref_id=tid, weight=0.6))

    rationale = (
        f"Severity {severity.value} (conf {severity_confidence:.2f}). "
        f"Category {category.value} (conf {category_confidence:.2f}). "
        f"{len(indicators)} IOCs, {len(candidates)} MITRE candidates."
    )
    latency_ms = int((time.perf_counter() - start) * 1000)
    return TriageResult(
        severity=severity,
        severity_confidence=severity_confidence,
        category=category,
        category_confidence=category_confidence,
        indicators=indicators,
        candidate_mitre_techniques=candidates,
        attribution=attribution,
        rationale=rationale,
        latency_ms=latency_ms,
    )