from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """A MITRE ATT&CK technique, e.g. T1059.001 PowerShell (Execution)."""

    id: str
    name: str
    tactic: str


@dataclass(frozen=True, slots=True)
class Evidence:
    """One read-only lookup the agent made, and what it returned.

    Recorded by code, not written by the model, so a report can never cite
    evidence that was not actually collected.
    """

    source: str
    query: str
    data: Any


@dataclass(frozen=True, slots=True)
class IncidentReport:
    alert_id: UUID
    summary: str
    techniques: tuple[AttackTechnique, ...]
    evidence: tuple[Evidence, ...]
    next_steps: tuple[str, ...]
    model: str
    created_at: datetime


class InvestigationError(Exception):
    """Raised by an investigator when it cannot produce a report."""
