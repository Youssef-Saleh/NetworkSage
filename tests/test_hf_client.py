"""Tests for HF client auth-failure handling."""

from __future__ import annotations

import pytest

from networksage.clients.hf_client import HFClient
from networksage.clients.iocs import extract_indicators


def test_unconfigured_returns_fallback() -> None:
    """Without HF_TOKEN, the client returns deterministic fallback."""
    client = HFClient()
    assert client.is_configured() is False
    scores = client.zero_shot_classify("phishing email", ["phishing", "malware"])
    assert "phishing" in scores
    assert all(0.0 <= v <= 1.0 for v in scores.values())


def test_extract_indicators_no_token_uses_regex(monkeypatch: pytest.MonkeyPatch) -> None:
    """IOC extraction falls back to regex when no HF token is configured."""
    monkeypatch.delenv("HF_TOKEN", raising=False)
    client = HFClient()
    indicators = extract_indicators("Malicious IP 198.51.100.42 and CVE-2024-1234", client)
    kinds = {i.type.value for i in indicators}
    assert "ipv4" in kinds
    assert "cve" in kinds


def test_auth_failure_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    """After a 401, subsequent calls skip the network entirely."""
    from networksage.clients import hf_client as hf_module

    monkeypatch.setenv("HF_TOKEN", "hf_definitely_not_a_real_token")

    class _FakeClient:
        def zero_shot_classification(self, **_: object) -> dict[str, float]:
            import httpx
            request = httpx.Request("POST", "https://example.com")
            response = httpx.Response(401, request=request)
            err = hf_module.HfHubHTTPError("401 Unauthorized", response=response)
            raise err

    client = HFClient()
    client._client = _FakeClient()  # type: ignore[attr-defined]
    assert client.is_configured() is True

    with pytest.raises(ValueError, match="HF auth failed"):
        client.zero_shot_classify("text", ["a", "b"])

    assert client._auth_failed is True
    assert client.is_configured() is False

    result = client.zero_shot_classify("text", ["a", "b"])
    assert isinstance(result, dict)
    assert "a" in result


def test_embedding_fallback_returns_unit_normalized_vectors() -> None:
    """Fallback embeddings are L2-normalized to length 256."""
    client = HFClient()
    vecs = client.feature_extraction(["hello world", "another phrase"])
    assert len(vecs) == 2
    assert len(vecs[0]) == 256
    norm = sum(v * v for v in vecs[0]) ** 0.5
    assert 0.99 < norm < 1.01


def test_embedding_fallback_is_deterministic_across_calls() -> None:
    """Same input must produce identical embeddings within a process.

    Critical for eval harness reproducibility. Without a stable hash,
    technique recall scores would vary between runs.
    """
    client = HFClient()
    a = client.feature_extraction(["ransomware encrypt files"])
    b = client.feature_extraction(["ransomware encrypt files"])
    assert a == b


def test_embedding_fallback_differs_for_different_text() -> None:
    """Sanity check that the embedding actually captures semantic content."""
    client = HFClient()
    a = client.feature_extraction(["ransomware encryption detected"])
    b = client.feature_extraction(["beach vacation planning"])
    assert a != b