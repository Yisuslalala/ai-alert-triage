from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ai_alert_triage.adapters.http.auth import AuthError, JwtVerifier, Principal
from ai_alert_triage.adapters.http.schemas import AlertIn, TriageResultOut
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.ports.triage import TriageRepository

READ_SCOPE = "alerts:read"
WRITE_SCOPE = "alerts:write"

_bearer = HTTPBearer(auto_error=False)


def _triage_use_case(request: Request) -> TriageAlert:
    use_case: TriageAlert = request.app.state.triage_alert
    return use_case


def _repository(request: Request) -> TriageRepository:
    repository: TriageRepository = request.app.state.repository
    return repository


def require_scope(scope: str) -> Callable[..., Principal | None]:
    def dependency(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    ) -> Principal | None:
        verifier: JwtVerifier | None = request.app.state.verifier
        if verifier is None:
            return None  # auth explicitly disabled for local development

        challenge = {"WWW-Authenticate": "Bearer"}
        if credentials is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token", challenge)
        try:
            principal = verifier.verify(credentials.credentials)
        except AuthError:
            # The reason stays server-side; clients only learn the token was rejected.
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "invalid token", challenge
            ) from None
        if scope not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"missing scope {scope}")
        return principal

    return dependency


def create_app(
    triage_alert: TriageAlert,
    repository: TriageRepository,
    verifier: JwtVerifier | None,
) -> FastAPI:
    """Build the API. ``verifier=None`` disables authentication (local development only)."""
    app = FastAPI(title="AI Alert Triage", version="0.1.0")
    app.state.triage_alert = triage_alert
    app.state.repository = repository
    app.state.verifier = verifier

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/alerts",
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_scope(WRITE_SCOPE))],
    )
    def receive_alert(
        payload: AlertIn,
        use_case: Annotated[TriageAlert, Depends(_triage_use_case)],
    ) -> TriageResultOut:
        result = use_case.execute(payload.to_domain())
        return TriageResultOut.from_domain(result)

    @app.get("/alerts/{alert_id}", dependencies=[Depends(require_scope(READ_SCOPE))])
    def get_alert(
        alert_id: UUID,
        repo: Annotated[TriageRepository, Depends(_repository)],
    ) -> TriageResultOut:
        result = repo.get(alert_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
        return TriageResultOut.from_domain(result)

    return app
