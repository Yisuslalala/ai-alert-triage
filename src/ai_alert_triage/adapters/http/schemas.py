from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import IncidentReport
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


class AttackTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str


class EvidenceOut(BaseModel):
    source: str
    query: str
    data: Any


class IncidentReportOut(BaseModel):
    alert_id: UUID
    summary: str
    techniques: list[AttackTechniqueOut]
    evidence: list[EvidenceOut]
    next_steps: list[str]
    model: str
    created_at: datetime

    @classmethod
    def from_domain(cls, report: IncidentReport) -> IncidentReportOut:
        return cls(
            alert_id=report.alert_id,
            summary=report.summary,
            techniques=[
                AttackTechniqueOut(id=t.id, name=t.name, tactic=t.tactic)
                for t in report.techniques
            ],
            evidence=[
                EvidenceOut(source=e.source, query=e.query, data=e.data) for e in report.evidence
            ],
            next_steps=list(report.next_steps),
            model=report.model,
            created_at=report.created_at,
        )
