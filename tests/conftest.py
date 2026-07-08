"""Pytest configuration for NetworkSage-X tests.

Forces the deterministic-fallback path during unit tests so they are
reproducible and don't make real HF Inference API calls. Eval and
demo scripts use the live API when HF_TOKEN is set in env.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _no_hf_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove any HF_TOKEN from the test environment."""
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGINGFACEHUB_API_TOKEN", raising=False)
    yield


@pytest.fixture
def reset_hf_env(monkeypatch: pytest.MonkeyPatch):
    """Helper for tests that want to simulate HF_TOKEN being set.

    Returns a setter that puts a value into HF_TOKEN for the duration of
    the test, then clears it on teardown.
    """

    def _set(token: str = "hf_test_fake_token") -> None:
        monkeypatch.setenv("HF_TOKEN", token)

    return _set