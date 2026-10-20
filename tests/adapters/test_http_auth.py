import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from ai_alert_triage.adapters.http.app import create_app
from ai_alert_triage.adapters.http.auth import AuthError, JwtVerifier
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import Classification
from tests.fakes import FakeClassifier, InMemoryTriageRepository, MarkingRedactor

ISSUER = "https://example.okta.com/oauth2/default"
AUDIENCE = "api://ai-alert-triage"
PROVIDER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
HMAC_SECRET = "a-shared-secret-of-at-least-32-bytes!"
ALERT = {"source": "edr", "title": "Encoded PowerShell"}


def make_token(
    key: Any = PROVIDER_KEY,
    algorithm: str = "RS256",
    **overrides: Any,
) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "soar-integration",
        "iat": now,
        "exp": now + 300,
        "scp": ["alerts:read", "alerts:write"],
    }
    claims.update(overrides)
    claims = {name: value for name, value in claims.items() if value is not None}
    return jwt.encode(claims, key, algorithm=algorithm)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def verifier() -> JwtVerifier:
    return JwtVerifier(ISSUER, AUDIENCE, key_resolver=lambda _token: PROVIDER_KEY.public_key())


@pytest.fixture
def client(verifier: JwtVerifier) -> TestClient:
    repo = InMemoryTriageRepository()
    classifier = FakeClassifier(Classification(Severity.LOW, "Benign", "fake-model"))
    use_case = TriageAlert(classifier, repo, MarkingRedactor())
    return TestClient(create_app(use_case, repo, verifier))


def test_health_needs_no_token(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


def test_valid_token_is_accepted(client: TestClient) -> None:
    response = client.post("/alerts", json=ALERT, headers=bearer(make_token()))
    assert response.status_code == 201

    alert_id = response.json()["alert_id"]
    assert client.get(f"/alerts/{alert_id}", headers=bearer(make_token())).status_code == 200


def test_missing_token_is_rejected(client: TestClient) -> None:
    response = client.post("/alerts", json=ALERT)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "token_factory",
    [
        pytest.param(lambda: make_token(key=ATTACKER_KEY), id="wrong-signing-key"),
        pytest.param(lambda: make_token(exp=int(time.time()) - 3600), id="expired"),
        pytest.param(lambda: make_token(aud="api://another-app"), id="wrong-audience"),
        pytest.param(lambda: make_token(iss="https://evil.example.com"), id="wrong-issuer"),
        pytest.param(lambda: make_token(sub=None), id="no-subject"),
        pytest.param(lambda: make_token(key=HMAC_SECRET, algorithm="HS256"), id="hs256"),
        pytest.param(lambda: "not-a-jwt", id="garbage"),
    ],
)
def test_bad_tokens_are_rejected(client: TestClient, token_factory: Callable[[], str]) -> None:
    response = client.post("/alerts", json=ALERT, headers=bearer(token_factory()))
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid token"}


def test_missing_scope_is_forbidden(client: TestClient) -> None:
    read_only = make_token(scp=["alerts:read"])

    response = client.post("/alerts", json=ALERT, headers=bearer(read_only))

    assert response.status_code == 403


@pytest.mark.parametrize(
    "claims",
    [
        {"scp": "alerts:read alerts:write"},  # Entra ID style
        {"scp": None, "scope": "alerts:write"},  # RFC 8693 style
    ],
)
def test_space_separated_scopes_are_understood(
    verifier: JwtVerifier, claims: dict[str, str | None]
) -> None:
    token = make_token(PROVIDER_KEY, "RS256", **claims)

    assert "alerts:write" in verifier.verify(token).scopes


def test_verifier_raises_auth_error() -> None:
    verifier = JwtVerifier(ISSUER, AUDIENCE, key_resolver=lambda _token: ATTACKER_KEY.public_key())
    with pytest.raises(AuthError):
        verifier.verify(make_token())
