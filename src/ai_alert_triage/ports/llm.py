from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class LLMMessage:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True, slots=True)
class LLMRequest:
    messages: tuple[LLMMessage, ...]
    schema_name: str
    json_schema: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LLMResponse:
    content: str
    model: str
    input_tokens: int
    output_tokens: int


class LLMError(Exception):
    """Raised by an LLM client when the provider call fails."""


class LLMClient(Protocol):
    """A provider that returns JSON matching the request's schema."""

    @property
    def provider(self) -> str: ...

    def complete(self, request: LLMRequest) -> LLMResponse: ...


@dataclass(frozen=True, slots=True)
class LLMAuditEntry:
    timestamp: datetime
    alert_id: UUID
    provider: str
    model: str
    messages: tuple[LLMMessage, ...]
    output: str | None
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    latency_ms: int
    error: str | None


class AuditLog(Protocol):
    def record(self, entry: LLMAuditEntry) -> None: ...
