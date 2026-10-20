from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, status

from ai_alert_triage.adapters.http.schemas import AlertIn, TriageResultOut
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.ports.triage import TriageRepository


def _triage_use_case(request: Request) -> TriageAlert:
    use_case: TriageAlert = request.app.state.triage_alert
    return use_case


def _repository(request: Request) -> TriageRepository:
    repository: TriageRepository = request.app.state.repository
    return repository


def create_app(triage_alert: TriageAlert, repository: TriageRepository) -> FastAPI:
    app = FastAPI(title="AI Alert Triage", version="0.1.0")
    app.state.triage_alert = triage_alert
    app.state.repository = repository

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/alerts", status_code=status.HTTP_201_CREATED)
    def receive_alert(
        payload: AlertIn,
        use_case: Annotated[TriageAlert, Depends(_triage_use_case)],
    ) -> TriageResultOut:
        result = use_case.execute(payload.to_domain())
        return TriageResultOut.from_domain(result)

    @app.get("/alerts/{alert_id}")
    def get_alert(
        alert_id: UUID,
        repo: Annotated[TriageRepository, Depends(_repository)],
    ) -> TriageResultOut:
        result = repo.get(alert_id)
        if result is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
        return TriageResultOut.from_domain(result)

    return app
