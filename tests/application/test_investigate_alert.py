from datetime import UTC, datetime

from ai_alert_triage.adapters.persistence.in_memory import InMemoryReportRepository
from ai_alert_triage.application.investigate_alert import InvestigateAlert
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import IncidentReport, InvestigationError
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import TriageResult

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


class FakeInvestigator:
    def __init__(self, fail: bool = False) -> None:
        self._fail = fail
        self.investigated: list[Alert] = []

    def investigate(self, alert: Alert) -> IncidentReport:
        self.investigated.append(alert)
        if self._fail:
            raise InvestigationError("fake failure")
        return IncidentReport(alert.id, "Report.", (), (), (), "fake-model", NOW)


def triage(alert: Alert, severity: Severity) -> TriageResult:
    return TriageResult(alert.id, severity, "summary", "fake-model", NOW)


def make_alert() -> Alert:
    return Alert("edr", "Encoded PowerShell", "", NOW)


def test_high_alerts_are_investigated_and_stored() -> None:
    reports = InMemoryReportRepository()
    alert = make_alert()

    report = InvestigateAlert(FakeInvestigator(), reports).execute(
        alert, triage(alert, Severity.HIGH)
    )

    assert report is not None
    assert reports.get(alert.id) == report


def test_low_alerts_are_not_investigated() -> None:
    investigator = FakeInvestigator()
    alert = make_alert()

    result = InvestigateAlert(investigator, InMemoryReportRepository()).execute(
        alert, triage(alert, Severity.LOW)
    )

    assert result is None
    assert investigator.investigated == []


def test_failed_investigation_stores_nothing() -> None:
    reports = InMemoryReportRepository()
    alert = make_alert()

    result = InvestigateAlert(FakeInvestigator(fail=True), reports).execute(
        alert, triage(alert, Severity.CRITICAL)
    )

    assert result is None
    assert reports.get(alert.id) is None
