from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ai_alert_triage.adapters.http.app import create_app
from ai_alert_triage.adapters.persistence.in_memory import InMemoryReportRepository
from ai_alert_triage.application.investigate_alert import InvestigateAlert
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import Evidence, IncidentReport
from ai_alert_triage.domain.mitre import CATALOG
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import Classification
from tests.fakes import FakeClassifier, InMemoryTriageRepository, MarkingRedactor

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


class FakeInvestigator:
    def investigate(self, alert: Alert) -> IncidentReport:
        evidence = Evidence("sentinelone", "sentinelone_get_threats(host_1)", [{"id": "1"}])
        return IncidentReport(
            alert.id, "Ransomware.", (CATALOG["T1486"],), (evidence,), ("Isolate host",), "m", NOW
        )


@pytest.fixture
def client() -> TestClient:
    repo = InMemoryTriageRepository()
    classifier = FakeClassifier(Classification(Severity.HIGH, "Looks bad", "fake-model"))
    use_case = TriageAlert(classifier, repo, MarkingRedactor(), clock=lambda: NOW)
    return TestClient(create_app(use_case, repo, verifier=None))


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_post_then_get_alert(client: TestClient) -> None:
    response = client.post("/alerts", json={"source": "edr", "title": "Encoded PowerShell"})

    assert response.status_code == 201
    body = response.json()
    assert body["severity"] == "high"
    assert body["requires_investigation"] is True

    fetched = client.get(f"/alerts/{body['alert_id']}")
    assert fetched.status_code == 200
    assert fetched.json() == body


def test_unknown_alert_returns_404(client: TestClient) -> None:
    assert client.get(f"/alerts/{uuid4()}").status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"title": "missing source"},
        {"source": "edr", "title": ""},
        {"source": "edr", "title": "t", "unexpected": "field"},
        {"source": "edr", "title": "t", "received_at": "2026-10-19T12:00:00"},
        {"source": "edr", "title": "x" * 501},
    ],
)
def test_invalid_payloads_are_rejected(client: TestClient, payload: dict[str, object]) -> None:
    assert client.post("/alerts", json=payload).status_code == 422


def test_high_alert_report_is_available_after_investigation() -> None:
    repo = InMemoryTriageRepository()
    reports = InMemoryReportRepository()
    classifier = FakeClassifier(Classification(Severity.CRITICAL, "Ransomware", "fake-model"))
    use_case = TriageAlert(classifier, repo, MarkingRedactor(), clock=lambda: NOW)
    investigate = InvestigateAlert(FakeInvestigator(), reports)
    client = TestClient(
        create_app(use_case, repo, verifier=None, investigate_alert=investigate, reports=reports)
    )

    alert_id = client.post("/alerts", json={"source": "edr", "title": "Ransomware"}).json()[
        "alert_id"
    ]
    response = client.get(f"/alerts/{alert_id}/report")

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == alert_id
    assert body["techniques"] == [
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
    ]
    assert body["evidence"][0]["source"] == "sentinelone"


def test_report_is_404_when_not_investigated(client: TestClient) -> None:
    assert client.get(f"/alerts/{uuid4()}/report").status_code == 404
