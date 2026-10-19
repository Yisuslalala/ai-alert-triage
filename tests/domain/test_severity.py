import pytest

from ai_alert_triage.domain.severity import Severity


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
def test_high_and_critical_require_investigation(severity: Severity) -> None:
    assert severity.requires_investigation


@pytest.mark.parametrize("severity", [Severity.LOW, Severity.MEDIUM, Severity.UNKNOWN])
def test_other_severities_do_not_require_investigation(severity: Severity) -> None:
    assert not severity.requires_investigation


def test_severity_parses_from_string() -> None:
    assert Severity("critical") is Severity.CRITICAL
