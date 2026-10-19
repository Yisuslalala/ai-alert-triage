from datetime import UTC, datetime

import pytest

from ai_alert_triage.domain.alert import Alert

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)


def test_alert_gets_unique_ids() -> None:
    a = Alert(source="siem", title="t", description="d", received_at=NOW)
    b = Alert(source="siem", title="t", description="d", received_at=NOW)
    assert a.id != b.id


@pytest.mark.parametrize("field", ["source", "title"])
def test_blank_required_fields_are_rejected(field: str) -> None:
    kwargs = {"source": "siem", "title": "t", "description": "d", "received_at": NOW}
    kwargs[field] = "   "
    with pytest.raises(ValueError):
        Alert(**kwargs)  # type: ignore[arg-type]


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError):
        Alert(source="siem", title="t", description="d", received_at=datetime(2026, 1, 1))
