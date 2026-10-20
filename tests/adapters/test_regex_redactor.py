from datetime import UTC, datetime

import pytest

from ai_alert_triage.adapters.redaction.regex import RegexRedactor, redact_text
from ai_alert_triage.domain.alert import Alert


@pytest.mark.parametrize(
    ("text", "leaked", "marker"),
    [
        ("login by jdoe@corp.com", "jdoe@corp.com", "[REDACTED_EMAIL]"),
        ("key AKIAABCDEFGHIJKLMNOP used", "AKIAABCDEFGHIJKLMNOP", "[REDACTED_AWS_KEY]"),
        ("password=Hunter2!", "Hunter2!", "[REDACTED_SECRET]"),
        ("bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", "eyJhbGciOi", "[REDACTED_JWT]"),
        ("ssn 123-45-6789", "123-45-6789", "[REDACTED_SSN]"),
        ("card 4111 1111 1111 1111", "4111 1111 1111 1111", "[REDACTED_CARD]"),
    ],
)
def test_sensitive_values_are_redacted(text: str, leaked: str, marker: str) -> None:
    redacted = redact_text(text)
    assert leaked not in redacted
    assert marker in redacted


def test_ip_addresses_are_kept_as_evidence() -> None:
    assert redact_text("connection from 10.0.0.5") == "connection from 10.0.0.5"


def test_redacts_nested_payload_without_mutating_original() -> None:
    alert = Alert(
        source="okta",
        title="Login for jdoe@corp.com",
        description="",
        received_at=datetime(2026, 10, 19, tzinfo=UTC),
        raw_payload={"actor": {"email": "jdoe@corp.com"}, "tags": ["token: abc123"], "count": 3},
    )

    redacted = RegexRedactor().redact(alert)

    assert redacted.title == "Login for [REDACTED_EMAIL]"
    assert redacted.raw_payload == {
        "actor": {"email": "[REDACTED_EMAIL]"},
        "tags": ["token=[REDACTED_SECRET]"],
        "count": 3,
    }
    assert redacted.id == alert.id
    assert alert.raw_payload["actor"]["email"] == "jdoe@corp.com"
