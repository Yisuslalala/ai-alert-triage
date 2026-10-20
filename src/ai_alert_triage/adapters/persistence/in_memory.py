from threading import Lock
from uuid import UUID

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import IncidentReport
from ai_alert_triage.domain.triage import TriageResult


class InMemoryTriageRepository:
    """Process-local storage. Data is lost on restart; Postgres replaces this later."""

    def __init__(self) -> None:
        self._alerts: dict[UUID, Alert] = {}
        self._results: dict[UUID, TriageResult] = {}
        self._lock = Lock()

    def save(self, alert: Alert, result: TriageResult) -> None:
        with self._lock:
            self._alerts[alert.id] = alert
            self._results[alert.id] = result

    def get(self, alert_id: UUID) -> TriageResult | None:
        with self._lock:
            return self._results.get(alert_id)


class InMemoryReportRepository:
    def __init__(self) -> None:
        self._reports: dict[UUID, IncidentReport] = {}
        self._lock = Lock()

    def save(self, report: IncidentReport) -> None:
        with self._lock:
            self._reports[report.alert_id] = report

    def get(self, alert_id: UUID) -> IncidentReport | None:
        with self._lock:
            return self._reports.get(alert_id)
