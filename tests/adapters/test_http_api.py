from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ai_alert_triage.adapters.http.app import create_app
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import Classification
from tests.fakes import FakeClassifier, InMemoryTriageRepository, MarkingRedactor

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


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
