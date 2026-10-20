from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from ai_alert_triage.adapters.persistence.sql.tables import AlertRow, TriageResultRow
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import TriageResult


def _as_utc(value: datetime) -> datetime:
    # SQLite drops the timezone; Postgres returns the session's local zone.
    # Normalize both so the API always answers in UTC.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class SqlAlchemyTriageRepository:
    def __init__(self, engine: Engine) -> None:
        self._sessions = sessionmaker(engine, expire_on_commit=False)

    def save(self, alert: Alert, result: TriageResult) -> None:
        with self._sessions.begin() as session:
            session.merge(
                AlertRow(
                    id=alert.id,
                    source=alert.source,
                    title=alert.title,
                    description=alert.description,
                    received_at=alert.received_at,
                    raw_payload=alert.raw_payload,
                )
            )
            session.merge(
                TriageResultRow(
                    alert_id=result.alert_id,
                    severity=result.severity.value,
                    summary=result.summary,
                    model=result.model,
                    triaged_at=result.triaged_at,
                )
            )

    def get(self, alert_id: UUID) -> TriageResult | None:
        with self._sessions() as session:
            row = session.get(TriageResultRow, alert_id)
            if row is None:
                return None
            return TriageResult(
                alert_id=row.alert_id,
                severity=Severity(row.severity),
                summary=row.summary,
                model=row.model,
                triaged_at=_as_utc(row.triaged_at),
            )
