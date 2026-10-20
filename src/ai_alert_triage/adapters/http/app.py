from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ai_alert_triage.adapters.http.auth import AuthError, JwtVerifier, Principal
from ai_alert_triage.adapters.http.schemas import AlertIn, IncidentReportOut, TriageResultOut
from ai_alert_triage.application.investigate_alert import InvestigateAlert
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.ports.investigation import ReportRepository
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


def _investigate_use_case(request: Request) -> InvestigateAlert | None:
    use_case: InvestigateAlert | None = request.app.state.investigate_alert
    return use_case


def _reports(request: Request) -> ReportRepository | None:
    reports: ReportRepository | None = request.app.state.reports
    return reports


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
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token", challenge) from None
        if scope not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"missing scope {scope}")
        return principal

    return dependency


def create_app(
    triage_alert: TriageAlert,
    repository: TriageRepository,
    verifier: JwtVerifier | None,
    investigate_alert: InvestigateAlert | None = None,
    reports: ReportRepository | None = None,
) -> FastAPI:
    """Build the API. ``verifier=None`` disables authentication (local development only).

    Without ``investigate_alert``, alerts are triaged but never investigated.
    """
    app = FastAPI(title="AI Alert Triage", version="0.1.0")
    app.state.triage_alert = triage_alert
    app.state.repository = repository
    app.state.verifier = verifier
    app.state.investigate_alert = investigate_alert
    app.state.reports = reports

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
        background: BackgroundTasks,
        use_case: Annotated[TriageAlert, Depends(_triage_use_case)],
        investigate: Annotated[InvestigateAlert | None, Depends(_investigate_use_case)],
    ) -> TriageResultOut:
        alert = payload.to_domain()
        result = use_case.execute(alert)
        if investigate is not None and result.requires_investigation:
            # Runs after the response, so the webhook caller is not kept waiting on the agent.
            background.add_task(investigate.execute, alert, result)
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

    @app.get("/alerts/{alert_id}/report", dependencies=[Depends(require_scope(READ_SCOPE))])
    def get_report(
        alert_id: UUID,
        reports: Annotated[ReportRepository | None, Depends(_reports)],
    ) -> IncidentReportOut:
        report = reports.get(alert_id) if reports is not None else None
        if report is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no incident report for this alert")
        return IncidentReportOut.from_domain(report)

    return app
