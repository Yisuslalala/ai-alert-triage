from typing import Protocol
from uuid import UUID

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.triage import Classification, TriageResult


class Redactor(Protocol):
    """Removes sensitive data from an alert before it leaves our boundary."""

    def redact(self, alert: Alert) -> Alert: ...


class AlertClassifier(Protocol):
    """Assigns a severity and summary to an alert.

    Implementations raise ClassificationError when they cannot classify.
    """

    def classify(self, alert: Alert) -> Classification: ...


class TriageRepository(Protocol):
    def save(self, alert: Alert, result: TriageResult) -> None: ...

    def get(self, alert_id: UUID) -> TriageResult | None: ...
