from datetime import UTC, datetime

from ai_alert_triage.application.triage_alert import UNCLASSIFIED_SUMMARY, TriageAlert
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import Classification
from tests.fakes import FakeClassifier, InMemoryTriageRepository, MarkingRedactor

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def make_alert() -> Alert:
    return Alert(
        source="sentinelone",
        title="Suspicious PowerShell",
        description="user jdoe@corp.com ran encoded command",
        received_at=NOW,
    )


def make_use_case(classifier: FakeClassifier) -> tuple[TriageAlert, InMemoryTriageRepository]:
    repo = InMemoryTriageRepository()
    use_case = TriageAlert(classifier, repo, MarkingRedactor(), clock=lambda: NOW)
    return use_case, repo


def test_classifies_and_stores_result() -> None:
    classification = Classification(Severity.HIGH, "Likely malware execution", "fake-model")
    classifier = FakeClassifier(classification)
    use_case, repo = make_use_case(classifier)
    alert = make_alert()

    result = use_case.execute(alert)

    assert result.alert_id == alert.id
    assert result.severity is Severity.HIGH
    assert result.summary == "Likely malware execution"
    assert result.model == "fake-model"
    assert result.triaged_at == NOW
    assert result.requires_investigation
    assert repo.get(alert.id) == result


def test_classifier_only_sees_redacted_alert() -> None:
    classifier = FakeClassifier(Classification(Severity.LOW, "noise", "fake-model"))
    use_case, repo = make_use_case(classifier)
    alert = make_alert()

    use_case.execute(alert)

    assert classifier.received[0].description == "[REDACTED]"
    # the original alert is what we keep
    assert repo.alerts[alert.id].description == alert.description


def test_classifier_failure_stores_alert_as_unknown() -> None:
    use_case, repo = make_use_case(FakeClassifier(fail=True))
    alert = make_alert()

    result = use_case.execute(alert)

    assert result.severity is Severity.UNKNOWN
    assert result.summary == UNCLASSIFIED_SUMMARY
    assert not result.requires_investigation
    assert repo.get(alert.id) == result
