"""Contract tests every TriageRepository must pass.

Postgres runs only when TEST_DATABASE_URL is set, e.g. with docker compose:
TEST_DATABASE_URL=postgresql+psycopg://triage:triage@localhost:5432/triage_test
"""

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine

from ai_alert_triage.adapters.persistence.in_memory import InMemoryTriageRepository
from ai_alert_triage.adapters.persistence.sql.repository import SqlAlchemyTriageRepository
from ai_alert_triage.adapters.persistence.sql.tables import Base
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import TriageResult
from ai_alert_triage.ports.triage import TriageRepository

POSTGRES_URL = os.environ.get("TEST_DATABASE_URL")
requires_postgres = pytest.mark.skipif(not POSTGRES_URL, reason="TEST_DATABASE_URL not set")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _sql_repository(url: str) -> Iterator[TriageRepository]:
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield SqlAlchemyTriageRepository(engine)
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param("postgres", marks=requires_postgres),
    ]
)
def repository(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[TriageRepository]:
    if request.param == "memory":
        yield InMemoryTriageRepository()
    elif request.param == "sqlite":
        yield from _sql_repository(f"sqlite:///{tmp_path / 'test.db'}")
    else:
        assert POSTGRES_URL is not None
        yield from _sql_repository(POSTGRES_URL)


def make_pair(severity: Severity = Severity.HIGH) -> tuple[Alert, TriageResult]:
    alert = Alert(
        source="sentinelone",
        title="Encoded PowerShell",
        description="ran on WS-01",
        received_at=datetime(2026, 10, 20, 8, 0, tzinfo=UTC),
        raw_payload={"host": "WS-01", "tags": ["edr", "powershell"], "pid": 4242},
    )
    result = TriageResult(
        alert_id=alert.id,
        severity=severity,
        summary="Likely malicious script.",
        model="gpt-test",
        triaged_at=datetime(2026, 10, 20, 8, 0, 5, tzinfo=UTC),
    )
    return alert, result


def test_get_returns_what_was_saved(repository: TriageRepository) -> None:
    alert, result = make_pair()

    repository.save(alert, result)

    assert repository.get(alert.id) == result


def test_get_unknown_id_returns_none(repository: TriageRepository) -> None:
    assert repository.get(uuid4()) is None


def test_saving_again_overwrites_result(repository: TriageRepository) -> None:
    alert, result = make_pair(Severity.UNKNOWN)
    repository.save(alert, result)

    retriaged = TriageResult(
        alert.id, Severity.CRITICAL, "Re-triaged.", "gpt-test", result.triaged_at
    )
    repository.save(alert, retriaged)

    assert repository.get(alert.id) == retriaged


def test_timestamps_come_back_in_utc(repository: TriageRepository) -> None:
    alert, result = make_pair()
    repository.save(alert, result)

    stored = repository.get(alert.id)

    assert stored is not None
    assert stored.triaged_at.utcoffset() == UTC.utcoffset(None)


@requires_postgres
def test_migrations_match_models(monkeypatch: pytest.MonkeyPatch) -> None:
    assert POSTGRES_URL is not None
    monkeypatch.setenv("DATABASE_URL", POSTGRES_URL)
    engine = create_engine(POSTGRES_URL)
    Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    engine.dispose()

    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    command.upgrade(config, "head")
    command.check(config)  # raises if models and migrations disagree
    command.downgrade(config, "base")
