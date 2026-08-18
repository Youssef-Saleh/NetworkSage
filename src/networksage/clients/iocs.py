"""IOC extraction utilities."""

from __future__ import annotations

import re
from typing import Any

from networksage.clients.hf_client import HFClient
from networksage.schemas.models import Indicator, IndicatorType

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z]{2,})+$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def classify_indicator_type(raw: str) -> IndicatorType | None:
    s = raw.strip()
    if not s:
        return None
    if _CVE_RE.match(s):
        return IndicatorType.CVE
    if _MITRE_RE.match(s.upper()):
        return IndicatorType.MITRE_TECHNIQUE
    if _EMAIL_RE.match(s):
        return IndicatorType.EMAIL
    if _URL_RE.match(s):
        return IndicatorType.URL
    if _SHA256_RE.match(s):
        return IndicatorType.SHA256
    if _SHA1_RE.match(s):
        return IndicatorType.SHA1
    if _MD5_RE.match(s):
        return IndicatorType.MD5
    if _IPV4_RE.match(s):
        return IndicatorType.IPV4
    if _DOMAIN_RE.match(s):
        return IndicatorType.DOMAIN
    return None


def extract_indicators(text: str, hf_client: HFClient, min_confidence: float = 0.5) -> list[Indicator]:
    if not text:
        return []
    try:
        raw_spans: list[dict[str, Any]] = hf_client.token_classify(text=text)
    except Exception:
        raw_spans = []
    out: list[Indicator] = []
    seen: set[tuple[str, IndicatorType]] = set()
    for span in raw_spans:
        word = span["word"].strip().strip(".,;:")
        score = float(span.get("score", 0.0))
        if score < min_confidence:
            continue
        kind = classify_indicator_type(word)
        if kind is None:
            continue
        key = (word.lower(), kind)
        if key in seen:
            continue
        seen.add(key)
        out.append(Indicator(value=word, type=kind, confidence=score, source_text=None, source_span=(int(span["start"]), int(span["end"]))))
    return out


def extract_indicators_from_alert(alert_dict: dict[str, Any], hf_client: HFClient) -> list[Indicator]:
    text_parts: list[str] = []
    for key in ("title", "description"):
        if alert_dict.get(key):
            text_parts.append(str(alert_dict[key]))
    for key in ("src_ip", "dst_ip", "destination_domain", "url", "file_hash", "user", "host"):
        val = alert_dict.get(key)
        if val:
            text_parts.append(f"{key}={val}")
    return extract_indicators("\n".join(text_parts), hf_client)