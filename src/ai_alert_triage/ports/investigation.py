"""Read-only context sources and investigation ports.

Every source here can only read. There is deliberately no port for response
actions (suspend a user, isolate a host): the agent suggests, a human acts.
Sources return the vendor's JSON shapes so a real REST client can replace a mock.
"""

from typing import Any, Protocol
from uuid import UUID

from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import IncidentReport


class IdentitySource(Protocol):
    """Identity provider, e.g. Okta (Users API and System Log API)."""

    def get_user(self, login: str) -> dict[str, Any] | None: ...

    def get_recent_events(self, login: str) -> list[dict[str, Any]]: ...


class EndpointSource(Protocol):
    """EDR platform, e.g. SentinelOne (Agents API and Threats API)."""

    def get_agent(self, hostname: str) -> dict[str, Any] | None: ...

    def get_threats(self, hostname: str) -> list[dict[str, Any]]: ...


class NetworkSource(Protocol):
    """Secure web gateway, e.g. Zscaler ZIA (URL Lookup API)."""

    def lookup_url(self, url: str) -> dict[str, Any]: ...


class Investigator(Protocol):
    """Builds an incident report. Raises InvestigationError when it cannot."""

    def investigate(self, alert: Alert) -> IncidentReport: ...


class ReportRepository(Protocol):
    def save(self, report: IncidentReport) -> None: ...

    def get(self, alert_id: UUID) -> IncidentReport | None: ...
