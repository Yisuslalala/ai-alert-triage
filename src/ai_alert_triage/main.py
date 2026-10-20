"""Composition root: the only place that picks concrete adapters."""

import openai

from ai_alert_triage.adapters.audit.jsonl import JsonlAuditLog
from ai_alert_triage.adapters.classification.keyword import KeywordClassifier
from ai_alert_triage.adapters.classification.llm import LLMClassifier, ModelPricing
from ai_alert_triage.adapters.http.app import create_app
from ai_alert_triage.adapters.llm.openai_chat import OpenAIChatClient
from ai_alert_triage.adapters.persistence.in_memory import InMemoryTriageRepository
from ai_alert_triage.adapters.redaction.regex import RegexRedactor
from ai_alert_triage.application.triage_alert import TriageAlert
from ai_alert_triage.config import Settings
from ai_alert_triage.ports.triage import AlertClassifier


def build_classifier(settings: Settings) -> AlertClassifier:
    if settings.llm_provider == "keyword":
        return KeywordClassifier()

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

    pricing = None
    if (
        settings.price_input_per_million_usd is not None
        and settings.price_output_per_million_usd is not None
    ):
        pricing = ModelPricing(
            settings.price_input_per_million_usd, settings.price_output_per_million_usd
        )

    return LLMClassifier(
        client=OpenAIChatClient(sdk_client, settings.llm_model, settings.llm_provider),
        audit_log=JsonlAuditLog(settings.audit_log_path),
        pricing=pricing,
    )


settings = Settings.from_env()
repository = InMemoryTriageRepository()
triage_alert = TriageAlert(
    classifier=build_classifier(settings),
    repository=repository,
    redactor=RegexRedactor(),
)

app = create_app(triage_alert, repository)
