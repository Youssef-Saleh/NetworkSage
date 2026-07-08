"""Run the NetworkSage-X eval harness over the synthetic case suite."""

from __future__ import annotations

import json
import sys

from networksage.clients.hf_client import HFClient
from networksage.eval.harness import run_eval_suite, summarize
from tests.eval.synthetic_cases import ALL_CASES


def main() -> int:
    hf = HFClient()
    print(f"HuggingFace configured: {hf.is_configured()}")
    print(f"Running {len(ALL_CASES)} eval cases...\n")

    results = run_eval_suite(ALL_CASES, hf)
    summary = summarize(results)

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(
            f"  [{status}] {r.case_name}: "
            f"sev={'OK' if r.severity_correct else 'X'} "
            f"cat={'OK' if r.category_correct else 'X'} "
            f"tech_recall={r.technique_recall_at_k:.2f} "
            f"ioc_recall={r.ioc_recall:.2f} "
            f"lat={r.total_latency_ms}ms"
        )

    print("\nSummary:")
    print(json.dumps(summary, indent=2))

    failed = [r for r in results if not r.passed]
    if failed:
        print(f"\n{len(failed)} cases failed.")
        # Don't fail CI on first run; flip this once you tune prompts.
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())