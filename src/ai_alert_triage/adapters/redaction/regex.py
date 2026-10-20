import re
from dataclasses import replace
from typing import Any

from ai_alert_triage.domain.alert import Alert

# Order matters: more specific patterns run first.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+"),
     r"\1=[REDACTED_SECRET]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED_CARD]"),
]


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


class RegexRedactor:
    """Pattern-based redaction of secrets and PII.

    IPs and hostnames are kept on purpose: they are the evidence the
    classifier needs, and they are not personal data on their own.
    """

    def redact(self, alert: Alert) -> Alert:
        return replace(
            alert,
            title=redact_text(alert.title),
            description=redact_text(alert.description),
            raw_payload=_redact_value(alert.raw_payload),
        )
