"""Enrichment Agent."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from networksage.clients.threat_intel import (
    AbuseIPDBClient,
    AlienVaultOTXClient,
    GreyNoiseClient,
    VirusTotalClient,
)
from networksage.schemas.models import (
    AttributionRef,
    EnrichmentResult,
    Indicator,
    IndicatorType,
    ThreatIntelHit,
    TriageResult,
)

_INDICATOR_TO_PROVIDERS: dict[IndicatorType, list[str]] = {
    IndicatorType.IPV4: ["abuseipdb", "virustotal", "alienvault_otx", "greynoise"],
    IndicatorType.IPV6: ["abuseipdb", "virustotal", "alienvault_otx"],
    IndicatorType.DOMAIN: ["virustotal", "alienvault_otx"],
    IndicatorType.URL: ["virustotal", "alienvault_otx"],
    IndicatorType.SHA256: ["virustotal", "alienvault_otx"],
    IndicatorType.SHA1: ["virustotal", "alienvault_otx"],
    IndicatorType.MD5: ["virustotal", "alienvault_otx"],
    IndicatorType.EMAIL: [],
    IndicatorType.CVE: [],
    IndicatorType.MITRE_TECHNIQUE: [],
}


def _build_provider_map() -> dict[str, Any]:
    return {
        "abuseipdb": AbuseIPDBClient(),
        "virustotal": VirusTotalClient(),
        "alienvault_otx": AlienVaultOTXClient(),
        "greynoise": GreyNoiseClient(),
    }


async def _query_provider(provider_name: str, indicator: Indicator, providers: dict[str, Any]) -> ThreatIntelHit | None:
    client = providers.get(provider_name)
    if client is None:
        return None
    try:
        return await asyncio.to_thread(client.lookup, indicator.value)
    except Exception:
        return None


async def _enrich_one(indicator: Indicator, providers: dict[str, Any]) -> list[ThreatIntelHit]:
    targets = _INDICATOR_TO_PROVIDERS.get(indicator.type, [])
    tasks = [_query_provider(name, indicator, providers) for name in targets]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def enrich_indicators(triage: TriageResult) -> EnrichmentResult:
    start = time.perf_counter()
    providers = _build_provider_map()

    async def _run() -> list[tuple[Indicator, list[ThreatIntelHit]]]:
        out: list[tuple[Indicator, list[ThreatIntelHit]]] = []
        for ind in triage.indicators:
            hits = await _enrich_one(ind, providers)
            out.append((ind, hits))
        return out

    pairs = asyncio.run(_run())

    all_hits: list[ThreatIntelHit] = []
    enriched_indicators: dict[str, dict[str, Any]] = {}
    attribution: list[AttributionRef] = []
    providers_queried: set[str] = set()
    providers_skipped: set[str] = set()

    for ind, hits in pairs:
        if not hits:
            providers_skipped.update(_INDICATOR_TO_PROVIDERS.get(ind.type, []))
            continue
        enriched_indicators[ind.value] = {
            "type": ind.type.value,
            "verdicts": {h.provider: {"verdict": h.verdict, "score": h.score} for h in hits},
        }
        all_hits.extend(hits)
        providers_queried.update(h.provider for h in hits)
        for h in hits:
            attribution.append(AttributionRef(kind="threat_intel", ref_id=f"{h.provider}:{ind.value}", snippet=f"{h.verdict} (score={h.score})", weight=0.7 if h.verdict == "malicious" else 0.3))

    rationale = (
        f"Queried {len(providers_queried)} threat intel providers across {len(triage.indicators)} indicators. "
        f"{sum(1 for h in all_hits if h.verdict == 'malicious')} malicious, "
        f"{sum(1 for h in all_hits if h.verdict == 'suspicious')} suspicious."
    )
    latency_ms = int((time.perf_counter() - start) * 1000)
    return EnrichmentResult(
        hits=all_hits,
        enriched_indicators=enriched_indicators,
        attribution=attribution,
        providers_queried=sorted(providers_queried),
        providers_skipped=sorted(providers_skipped),
        rationale=rationale,
        latency_ms=latency_ms,
    )