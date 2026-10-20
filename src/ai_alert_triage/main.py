"""Composition root: the only place that picks concrete adapters."""

from ai_alert_triage.adapters.classification.keyword import KeywordClassifier
from ai_alert_triage.adapters.http.app import create_app
from ai_alert_triage.adapters.persistence.in_memory import InMemoryTriageRepository
from ai_alert_triage.adapters.redaction.regex import RegexRedactor
from ai_alert_triage.application.triage_alert import TriageAlert

repository = InMemoryTriageRepository()
triage_alert = TriageAlert(
    classifier=KeywordClassifier(),
    repository=repository,
    redactor=RegexRedactor(),
)

app = create_app(triage_alert, repository)
