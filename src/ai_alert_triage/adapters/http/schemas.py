from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import TriageResult


class AlertIn(BaseModel):
    # Size limits keep a single webhook from flooding memory or the LLM context.
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=10_000)
    received_at: AwareDatetime | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    def to_domain(self) -> Alert:
        return Alert(
            source=self.source,
            title=self.title,
            description=self.description,
            received_at=self.received_at or datetime.now(UTC),
            raw_payload=self.raw_payload,
        )


class TriageResultOut(BaseModel):
    alert_id: UUID
    severity: Severity
    summary: str
    model: str
    triaged_at: datetime
    requires_investigation: bool

    @classmethod
    def from_domain(cls, result: TriageResult) -> TriageResultOut:
        return cls(
            alert_id=result.alert_id,
            severity=result.severity,
            summary=result.summary,
            model=result.model,
            triaged_at=result.triaged_at,
            requires_investigation=result.requires_investigation,
        )
