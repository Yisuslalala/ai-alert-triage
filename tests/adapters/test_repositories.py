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

from ai_alert_triage.adapters.persistence.in_memory import (
    InMemoryReportRepository,
    InMemoryTriageRepository,
)
from ai_alert_triage.adapters.persistence.sql.repository import (
    SqlAlchemyReportRepository,
    SqlAlchemyTriageRepository,
)
from ai_alert_triage.adapters.persistence.sql.tables import Base
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import Evidence, IncidentReport
from ai_alert_triage.domain.mitre import CATALOG
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import TriageResult
from ai_alert_triage.ports.investigation import ReportRepository
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


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param("postgres", marks=requires_postgres),
    ]
)
def stores(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[tuple[TriageRepository, ReportRepository]]:
    if request.param == "memory":
        yield InMemoryTriageRepository(), InMemoryReportRepository()
        return
    url = f"sqlite:///{tmp_path / 'test.db'}" if request.param == "sqlite" else POSTGRES_URL
    assert url is not None
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield SqlAlchemyTriageRepository(engine), SqlAlchemyReportRepository(engine)
    Base.metadata.drop_all(engine)
    engine.dispose()


def make_report(alert: Alert) -> IncidentReport:
    return IncidentReport(
        alert_id=alert.id,
        summary="Encoded PowerShell from a phishing attachment.",
        techniques=(CATALOG["T1566.001"], CATALOG["T1059.001"]),
        evidence=(
            Evidence(
                "sentinelone",
                "sentinelone_get_threats(host_1)",
                [{"threatInfo": {"threatName": "invoice.ps1"}, "indicators": []}],
            ),
            Evidence("okta", "okta_get_user(user_1)", None),
        ),
        next_steps=("Isolate WS-01.", "Reset credentials."),
        model="gpt-test",
        created_at=datetime(2026, 10, 20, 8, 1, tzinfo=UTC),
    )


def test_report_round_trips(stores: tuple[TriageRepository, ReportRepository]) -> None:
    triage, reports = stores
    alert, result = make_pair()
    triage.save(alert, result)
    report = make_report(alert)

    reports.save(report)

    assert reports.get(alert.id) == report
    assert reports.get(uuid4()) is None


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
