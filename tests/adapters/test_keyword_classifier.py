from datetime import UTC, datetime

import pytest

from ai_alert_triage.adapters.classification.keyword import KeywordClassifier
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity


def alert(title: str, description: str = "") -> Alert:
    return Alert("edr", title, description, datetime(2026, 10, 19, tzinfo=UTC))


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("Ransomware note dropped", Severity.CRITICAL),
        ("Encoded PowerShell executed", Severity.HIGH),
        ("Brute force against VPN", Severity.MEDIUM),
        ("Scheduled scan finished", Severity.LOW),
    ],
)
def test_classifies_by_keywords(title: str, expected: Severity) -> None:
    assert KeywordClassifier().classify(alert(title)).severity is expected


def test_most_severe_match_wins() -> None:
    result = KeywordClassifier().classify(alert("Suspicious malware", "mimikatz detected"))
    assert result.severity is Severity.CRITICAL
