"""Quick demo: run a single alert through the pipeline and print the report.

Usage:
    python -m scripts.demo
"""

from __future__ import annotations

from networksage.agents.graph import run_alert
from networksage.schemas.models import (
    AlertSource,
    NetworkAlert,
)


SAMPLE_ALERT = NetworkAlert(
    alert_id="DEMO-001",
    source=AlertSource.SURICATA,
    title="Suspicious email with CVE-2024-1234 from attacker@evil.example",
    description=(
        "Email from attacker@evil.example with attachment exploiting CVE-2024-1234. "
        "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
        "User clicked the link, redirected to evil.example/payload."
    ),
    src_ip="10.0.0.45",
    destination_domain="evil.example",
    file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    url="http://evil.example/payload",
)


def main() -> None:
    state = run_alert(SAMPLE_ALERT)
    if state.response is None:
        print("Pipeline did not produce a response.")
        return
    print(state.response.report_markdown)


if __name__ == "__main__":
    main()