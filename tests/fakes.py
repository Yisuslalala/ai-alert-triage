from dataclasses import replace
from typing import Any
from uuid import UUID

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.triage import Classification, ClassificationError, TriageResult


class FakeClassifier:
    def __init__(self, classification: Classification | None = None, fail: bool = False) -> None:
        self._classification = classification
        self._fail = fail
        self.received: list[Alert] = []

    def classify(self, alert: Alert) -> Classification:
        self.received.append(alert)
        if self._fail or self._classification is None:
            raise ClassificationError("fake failure")
        return self._classification


class InMemoryTriageRepository:
    def __init__(self) -> None:
        self.alerts: dict[UUID, Alert] = {}
        self.results: dict[UUID, TriageResult] = {}

    def save(self, alert: Alert, result: TriageResult) -> None:
        self.alerts[alert.id] = alert
        self.results[alert.id] = result

    def get(self, alert_id: UUID) -> TriageResult | None:
        return self.results.get(alert_id)


class MarkingRedactor:
    """Replaces the description so tests can tell redaction happened."""

    def redact(self, alert: Alert) -> Alert:
        return replace(alert, description="[REDACTED]")

    def redact_data(self, value: Any) -> Any:
        return value
