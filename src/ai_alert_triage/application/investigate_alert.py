import logging

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import IncidentReport, InvestigationError
from ai_alert_triage.domain.triage import TriageResult
from ai_alert_triage.ports.investigation import Investigator, ReportRepository

logger = logging.getLogger(__name__)


class InvestigateAlert:
    """Use case: investigate high and critical alerts and store the incident report.

    A failed investigation is logged and skipped; the triage result already
    puts the alert in front of an analyst.
    """

    def __init__(self, investigator: Investigator, reports: ReportRepository) -> None:
        self._investigator = investigator
        self._reports = reports

    def execute(self, alert: Alert, triage: TriageResult) -> IncidentReport | None:
        if not triage.requires_investigation:
            return None
        try:
            report = self._investigator.investigate(alert)
        except InvestigationError:
            logger.exception("investigation of alert %s failed", alert.id)
            return None
        self._reports.save(report)
        return report
