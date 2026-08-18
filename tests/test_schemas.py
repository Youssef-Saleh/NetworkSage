"""Schema and IOC classifier tests."""

from networksage.clients.iocs import classify_indicator_type
from networksage.schemas.models import (
    AttackCategory,
    AttributionRef,
    Indicator,
    IndicatorType,
    NetworkAlert,
    Severity,
    TriageResult,
)


def test_classify_indicator_type_ipv4() -> None:
    assert classify_indicator_type("198.51.100.42") == IndicatorType.IPV4


def test_classify_indicator_type_sha256() -> None:
    assert classify_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == IndicatorType.SHA256


def test_classify_indicator_type_cve() -> None:
    assert classify_indicator_type("CVE-2024-1234") == IndicatorType.CVE


def test_classify_indicator_type_mitre() -> None:
    assert classify_indicator_type("T1059.001") == IndicatorType.MITRE_TECHNIQUE


def test_classify_indicator_type_domain() -> None:
    assert classify_indicator_type("evil-domain.example") == IndicatorType.DOMAIN


def test_classify_indicator_type_unknown() -> None:
    assert classify_indicator_type("not an indicator") is None


def test_alert_validation_rejects_empty_id() -> None:
    import pytest

    with pytest.raises(ValueError):
        NetworkAlert(alert_id="", title="x")


def test_attribution_ref_weight_bounds() -> None:
    import pytest

    with pytest.raises(ValueError):
        AttributionRef(kind="ioc", ref_id="x", weight=1.5)


def test_triage_result_confidence_bounds() -> None:
    import pytest

    with pytest.raises(ValueError):
        TriageResult(
            severity=Severity.HIGH,
            severity_confidence=1.5,
            category=AttackCategory.PHISHING,
            category_confidence=0.5,
            attribution=[],
            rationale="x",
            indicators=[],
        )


def test_indicator_confidence_bounds() -> None:
    import pytest

    with pytest.raises(ValueError):
        Indicator(value="1.2.3.4", type=IndicatorType.IPV4, confidence=-0.1)