"""Synthetic eval fixtures for NetworkSage-X.

These cover common SOC alert patterns. Each case has ground-truth severity,
category, expected MITRE techniques, and expected IOCs so the eval harness
can compute pass/fail.
"""

from networksage.eval.harness import EvalCase
from networksage.schemas.models import (
    AlertSource,
    AttackCategory,
    NetworkAlert,
    Severity,
)


CASE_PHISHING_001 = EvalCase(
    name="phishing_001_spearphish_with_cve",
    alert=NetworkAlert(
        alert_id="EVAL-PHISH-001",
        source=AlertSource.SURICATA,
        title="Suspicious email with CVE-2024-1234 attachment from evil-domain.example",
        description=(
            "User received an email from attacker@evil-domain.example containing an attachment "
            "exploiting CVE-2024-1234. The attachment hashes to "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
            "User clicked the link, which redirected to evil-domain.example/payload."
        ),
        src_ip="10.0.0.45",
        destination_domain="evil-domain.example",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        url="http://evil-domain.example/payload",
    ),
    expected_severity=Severity.HIGH,
    expected_category=AttackCategory.PHISHING,
    expected_techniques=["T1566", "T1190"],
    expected_iocs=[
        "evil-domain.example",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "CVE-2024-1234",
    ],
)


CASE_C2_001 = EvalCase(
    name="c2_001_beacon_to_known_bad_ip",
    alert=NetworkAlert(
        alert_id="EVAL-C2-001",
        source=AlertSource.ZEEK,
        title="Periodic beacon to 198.51.100.42 from internal host",
        description=(
            "Host 10.0.0.123 is making outbound connections every 60 seconds to "
            "198.51.100.42 on port 443. The destination IP is associated with known "
            "command and control infrastructure."
        ),
        src_ip="10.0.0.123",
        dst_ip="198.51.100.42",
        dst_port=443,
        protocol="tcp",
    ),
    expected_severity=Severity.HIGH,
    expected_category=AttackCategory.COMMAND_AND_CONTROL,
    expected_techniques=["T1071", "T1098"],
    expected_iocs=["198.51.100.42"],
)


CASE_RANSOMWARE_001 = EvalCase(
    name="ransomware_001_volume_encryption",
    alert=NetworkAlert(
        alert_id="EVAL-RANSOM-001",
        source=AlertSource.WAZUH,
        title="Mass file encryption detected on file server",
        description=(
            "File server FS01 shows rapid encryption of 5000+ files in /shared. "
            "Process tree shows powershell.exe spawning from winword.exe. "
            "Encoded command observed: -EncodedCommand ZQBjAGgAbwAgACIAdABlAH"
            "MAdAB..."
        ),
        host="FS01",
        user="jdoe",
    ),
    expected_severity=Severity.CRITICAL,
    expected_category=AttackCategory.IMPACT,
    expected_techniques=["T1486", "T1059.001", "T1566"],
    expected_iocs=[],
)


CASE_RECON_001 = EvalCase(
    name="recon_001_port_scan",
    alert=NetworkAlert(
        alert_id="EVAL-RECON-001",
        source=AlertSource.SURICATA,
        title="External port scan from 203.0.113.7",
        description=(
            "Source IP 203.0.113.7 performed a TCP SYN scan across the DMZ, "
            "probing 1000+ ports on 10 hosts within 5 minutes."
        ),
        src_ip="203.0.113.7",
    ),
    expected_severity=Severity.MEDIUM,
    expected_category=AttackCategory.RECONNAISSANCE,
    expected_techniques=["T1071"],
    expected_iocs=["203.0.113.7"],
)


CASE_MALWARE_001 = EvalCase(
    name="malware_001_dropper_download",
    alert=NetworkAlert(
        alert_id="EVAL-MALWARE-001",
        source=AlertSource.ELASTIC,
        title="EDR detected suspicious dropper execution",
        description=(
            "Endpoint EDR flagged powershell.exe downloading a payload from "
            "malicious-c2.example/exec.ps1. The downloaded file hashes to "
            "da39a3ee5e6b4b0d3255bfef95601890afd80709. The command shows "
            "IEX (New-Object Net.WebClient).DownloadString usage."
        ),
        host="WS-204",
        destination_domain="malicious-c2.example",
        file_hash="da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ),
    expected_severity=Severity.HIGH,
    expected_category=AttackCategory.MALWARE,
    expected_techniques=["T1059.001", "T1071", "T1027"],
    expected_iocs=[
        "malicious-c2.example",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ],
)


CASE_LATERAL_001 = EvalCase(
    name="lateral_001_pass_the_hash",
    alert=NetworkAlert(
        alert_id="EVAL-LAT-001",
        source=AlertSource.SPLUNK,
        title="Pass-the-hash detection across multiple hosts",
        description=(
            "NTLM authentication observed from host 10.0.0.50 to hosts 10.0.0.51, "
            "10.0.0.52, 10.0.0.53 within 2 minutes using the same hash. "
            "Indicates lateral movement using compromised credentials."
        ),
        src_ip="10.0.0.50",
    ),
    expected_severity=Severity.CRITICAL,
    expected_category=AttackCategory.LATERAL_MOVEMENT,
    expected_techniques=["T1078", "T1098"],
    expected_iocs=[],
)


CASE_INFO_001 = EvalCase(
    name="info_001_policy_violation",
    alert=NetworkAlert(
        alert_id="EVAL-INFO-001",
        source=AlertSource.GENERIC,
        title="Informational: USB device connected to workstation",
        description="User plugged in a USB drive. No policy violation flags.",
        host="WS-101",
        user="asmith",
    ),
    expected_severity=Severity.INFO,
    expected_category=AttackCategory.UNKNOWN,
    expected_techniques=[],
    expected_iocs=[],
)


ALL_CASES = [
    CASE_PHISHING_001,
    CASE_C2_001,
    CASE_RANSOMWARE_001,
    CASE_RECON_001,
    CASE_MALWARE_001,
    CASE_LATERAL_001,
    CASE_INFO_001,
]