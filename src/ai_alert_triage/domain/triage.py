from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from ai_alert_triage.domain.severity import Severity


@dataclass(frozen=True, slots=True)
class Classification:
    """What a classifier (e.g. an LLM) decided about an alert."""

    severity: Severity
    summary: str
    model: str


@dataclass(frozen=True, slots=True)
class TriageResult:
    alert_id: UUID
    severity: Severity
    summary: str
    model: str
    triaged_at: datetime

    @property
    def requires_investigation(self) -> bool:
        return self.severity.requires_investigation


class ClassificationError(Exception):
    """Raised by a classifier when it cannot produce a classification."""
