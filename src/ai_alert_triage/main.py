"""Composition root: the only place that picks concrete adapters."""

import openai
from sqlalchemy import Engine, create_engine

from ai_alert_triage.adapters.audit.jsonl import JsonlAuditLog
from ai_alert_triage.adapters.classification.keyword import KeywordClassifier
from ai_alert_triage.adapters.classification.llm import LLMClassifier, ModelPricing
from ai_alert_triage.adapters.context.okta import MockOktaIdentitySource
from ai_alert_triage.adapters.context.sentinelone import MockSentinelOneEndpointSource
from ai_alert_triage.adapters.context.zscaler import MockZscalerNetworkSource
from ai_alert_triage.adapters.http.app import create_app
from ai_alert_triage.adapters.http.auth import JwtVerifier
from ai_alert_triage.adapters.investigation.llm_agent import LLMInvestigationAgent
from ai_alert_triage.adapters.llm.openai_chat import OpenAIChatClient
from ai_alert_triage.adapters.persistence.in_memory import (
    InMemoryReportRepository,
    InMemoryTriageRepository,
)
from ai_alert_triage.adapters.persistence.sql.repository import (
    SqlAlchemyReportRepository,
    SqlAlchemyTriageRepository,
)
from ai_alert_triage.adapters.redaction.regex import RegexRedactor
from ai_alert_triage.application.investigate_alert import InvestigateAlert
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.config import Settings
from ai_alert_triage.ports.investigation import ReportRepository
from ai_alert_triage.ports.llm import AuditLog, LLMClient
from ai_alert_triage.ports.triage import AlertClassifier, Redactor, TriageRepository


def build_llm_client(settings: Settings) -> LLMClient | None:
    if settings.llm_provider == "keyword":
        return None

    assert settings.llm_model is not None  # guaranteed by Settings validation
    if settings.llm_provider == "openai":
        sdk_client: openai.OpenAI = openai.OpenAI(api_key=settings.openai_api_key)
    else:
        assert settings.azure_endpoint is not None
        sdk_client = openai.AzureOpenAI(
            api_key=settings.azure_api_key,
            azure_endpoint=settings.azure_endpoint,
            api_version=settings.azure_api_version,
        )
    return OpenAIChatClient(sdk_client, settings.llm_model, settings.llm_provider)


def build_pricing(settings: Settings) -> ModelPricing | None:
    if (
        settings.price_input_per_million_usd is None
        or settings.price_output_per_million_usd is None
    ):
        return None
    return ModelPricing(settings.price_input_per_million_usd, settings.price_output_per_million_usd)


def build_classifier(
    llm: LLMClient | None, audit_log: AuditLog, pricing: ModelPricing | None
) -> AlertClassifier:
    if llm is None:
        return KeywordClassifier()
    return LLMClassifier(client=llm, audit_log=audit_log, pricing=pricing)


def build_investigation(
    llm: LLMClient | None,
    audit_log: AuditLog,
    pricing: ModelPricing | None,
    redactor: Redactor,
    reports: ReportRepository,
) -> InvestigateAlert | None:
    if llm is None:
        return None  # the agent needs an LLM; keyword mode only triages
    agent = LLMInvestigationAgent(
        client=llm,
        audit_log=audit_log,
        redactor=redactor,
        # Mocks with the vendors' response shapes; replace with REST clients per tenant.
        identity=MockOktaIdentitySource(),
        endpoint=MockSentinelOneEndpointSource(),
        network=MockZscalerNetworkSource(),
        pricing=pricing,
    )
    return InvestigateAlert(agent, reports)


def build_engine(settings: Settings) -> Engine | None:
    if settings.database_url is None:
        return None
    # Tables come from Alembic migrations (`alembic upgrade head`), not create_all.
    return create_engine(settings.database_url, pool_pre_ping=True)


def build_verifier(settings: Settings) -> JwtVerifier | None:
    if settings.auth_disabled:
        return None
    assert settings.auth_issuer and settings.auth_audience and settings.auth_jwks_url
    return JwtVerifier.from_jwks(
        settings.auth_issuer, settings.auth_audience, settings.auth_jwks_url
    )


settings = Settings.from_env()
engine = build_engine(settings)
repository: TriageRepository = (
    SqlAlchemyTriageRepository(engine) if engine else InMemoryTriageRepository()
)
reports: ReportRepository = (
    SqlAlchemyReportRepository(engine) if engine else InMemoryReportRepository()
)
redactor = RegexRedactor()
llm = build_llm_client(settings)
audit_log = JsonlAuditLog(settings.audit_log_path)
pricing = build_pricing(settings)

app = create_app(
    TriageAlert(build_classifier(llm, audit_log, pricing), repository, redactor),
    repository,
    build_verifier(settings),
    investigate_alert=build_investigation(llm, audit_log, pricing, redactor, reports),
    reports=reports,
)
