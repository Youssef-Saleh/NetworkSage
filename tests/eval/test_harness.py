"""Run the eval harness over the synthetic case suite."""

from tests.eval.synthetic_cases import ALL_CASES
from networksage.clients.hf_client import HFClient
from networksage.eval.harness import run_eval_suite, summarize


def test_eval_suite_summary() -> None:
    """Smoke test: every eval case runs end-to-end without crashing."""
    hf = HFClient()
    results = run_eval_suite(ALL_CASES, hf)
    summary = summarize(results)
    # Sanity: every case produced a result, and each has the expected shape.
    assert summary["cases"] == len(ALL_CASES)
    for r in results:
        assert r.case_name
        assert r.attribution_chain_size >= 0
        assert r.total_latency_ms >= 0
    print("Eval summary:", summary)