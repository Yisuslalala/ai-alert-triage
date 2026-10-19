from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class Alert:
    """A security alert as received from an upstream tool (SIEM, EDR, ...)."""

    source: str
    title: str
    description: str
    received_at: datetime
    raw_payload: dict[str, Any] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("alert source must not be empty")
        if not self.title.strip():
            raise ValueError("alert title must not be empty")
        if self.received_at.tzinfo is None:
            raise ValueError("received_at must be timezone-aware")
