"""Threat intel provider clients with deterministic mocks for dev / CI."""

from __future__ import annotations

import hashlib
import os
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from networksage.schemas.models import ThreatIntelHit


def _mock_verdict(indicator: str, provider: str) -> ThreatIntelHit:
    h = int(hashlib.sha256(f"{provider}:{indicator}".encode()).hexdigest()[:8], 16)
    bucket = h % 100
    if bucket < 60:
        verdict, score = "clean", 5.0
    elif bucket < 85:
        verdict, score = "suspicious", 45.0
    elif bucket < 97:
        verdict, score = "malicious", 80.0
    else:
        verdict, score = "unknown", None
    return ThreatIntelHit(provider=provider, indicator=indicator, verdict=verdict, score=score, details={"mock": True, "seed": h})


class AbuseIPDBClient:
    name = "abuseipdb"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def lookup(self, ip: str) -> ThreatIntelHit:
        if not self.is_configured():
            return _mock_verdict(ip, self.name)
        assert self.api_key is not None  # is_configured() guarantees this
        try:
            resp = httpx.get(
                f"{self.base_url}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = float(data.get("abuseConfidenceScore", 0))
            verdict = "malicious" if score >= 80 else "suspicious" if score >= 25 else "clean"
            return ThreatIntelHit(provider=self.name, indicator=ip, verdict=verdict, score=score, details={"countryCode": data.get("countryCode"), "isp": data.get("isp")})
        except httpx.HTTPError:
            return _mock_verdict(ip, self.name)


class VirusTotalClient:
    name = "virustotal"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def lookup(self, indicator: str) -> ThreatIntelHit:
        if not self.is_configured():
            return _mock_verdict(indicator, self.name)
        assert self.api_key is not None
        try:
            if _looks_like_hash(indicator):
                url = f"{self.base_url}/files/{indicator}"
            elif _looks_like_ip(indicator):
                url = f"{self.base_url}/ip_addresses/{indicator}"
            elif _looks_like_domain(indicator):
                url = f"{self.base_url}/domains/{indicator}"
            else:
                return ThreatIntelHit(provider=self.name, indicator=indicator, verdict="unknown", score=None)
            resp = httpx.get(url, headers={"x-apikey": self.api_key}, timeout=10.0)
            resp.raise_for_status()
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values()) or 1
            score = (malicious / total) * 100.0
            verdict = "malicious" if score >= 10 else "suspicious" if score > 0 else "clean"
            return ThreatIntelHit(provider=self.name, indicator=indicator, verdict=verdict, score=score, details={"malicious": malicious, "total": total})
        except httpx.HTTPError:
            return _mock_verdict(indicator, self.name)


class AlienVaultOTXClient:
    name = "alienvault_otx"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("ALIENVAULT_OTX_API_KEY")
        self.base_url = "https://otx.alienvault.com/api/v1"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def lookup(self, indicator: str, indicator_type: str = "IPv4") -> ThreatIntelHit:
        if not self.is_configured():
            return _mock_verdict(indicator, self.name)
        assert self.api_key is not None
        try:
            type_map = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "sha256": "file", "sha1": "file", "md5": "file", "url": "url"}
            otx_type = type_map.get(indicator_type.lower(), "IPv4")
            url = f"{self.base_url}/indicators/{otx_type}/{indicator}/general"
            resp = httpx.get(url, headers={"X-OTX-API-KEY": self.api_key}, timeout=10.0)
            resp.raise_for_status()
            pulse_count = int(resp.json().get("pulse_info", {}).get("count", 0))
            verdict = "malicious" if pulse_count >= 5 else "suspicious" if pulse_count > 0 else "clean"
            score = min(pulse_count * 10.0, 100.0)
            return ThreatIntelHit(provider=self.name, indicator=indicator, verdict=verdict, score=score, details={"pulse_count": pulse_count})
        except httpx.HTTPError:
            return _mock_verdict(indicator, self.name)


class GreyNoiseClient:
    name = "greynoise"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("GREYNOISE_API_KEY")
        self.base_url = "https://api.greynoise.io"

    def is_configured(self) -> bool:
        return bool(self.api_key)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    def lookup(self, ip: str) -> ThreatIntelHit:
        if not self.is_configured():
            return _mock_verdict(ip, self.name)
        assert self.api_key is not None
        try:
            resp = httpx.get(f"{self.base_url}/v3/community/{ip}", headers={"key": self.api_key}, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            classification = data.get("classification", "unknown")
            verdict_map = {"malicious": "malicious", "benign": "clean", "unknown": "unknown"}
            verdict = verdict_map.get(classification, "unknown")
            return ThreatIntelHit(provider=self.name, indicator=ip, verdict=verdict, details={"noise": bool(data.get("noise")), "riot": bool(data.get("riot")), "name": data.get("name")}, score=None)
        except httpx.HTTPError:
            return _mock_verdict(ip, self.name)


def default_provider_registry() -> dict[str, Any]:
    return {
        "abuseipdb": AbuseIPDBClient(),
        "virustotal": VirusTotalClient(),
        "alienvault_otx": AlienVaultOTXClient(),
        "greynoise": GreyNoiseClient(),
    }


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _looks_like_domain(s: str) -> bool:
    return "." in s and " " not in s and not _looks_like_ip(s)


def _looks_like_hash(s: str) -> bool:
    return len(s) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in s)