from collections.abc import Callable
from datetime import UTC, datetime

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import ClassificationError, TriageResult
from ai_alert_triage.ports.triage import AlertClassifier, Redactor, TriageRepository

UNCLASSIFIED_SUMMARY = "Automatic classification failed; manual review required."


class TriageAlert:
    """Use case: redact an alert, classify it, and store the result.

    A classifier failure never drops the alert: it is stored as UNKNOWN
    so an analyst can still pick it up.
    """

    def __init__(
        self,
        classifier: AlertClassifier,
        repository: TriageRepository,
        redactor: Redactor,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._classifier = classifier
        self._repository = repository
        self._redactor = redactor
        self._clock = clock

    def execute(self, alert: Alert) -> TriageResult:
        redacted = self._redactor.redact(alert)

        try:
            classification = self._classifier.classify(redacted)
            severity = classification.severity
            summary = classification.summary
            model = classification.model
        except ClassificationError:
            severity = Severity.UNKNOWN
            summary = UNCLASSIFIED_SUMMARY
            model = "none"

        result = TriageResult(
            alert_id=alert.id,
            severity=severity,
            summary=summary,
            model=model,
            triaged_at=self._clock(),
        )
        self._repository.save(alert, result)
        return result
