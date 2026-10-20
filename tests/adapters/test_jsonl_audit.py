import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ai_alert_triage.adapters.audit.jsonl import JsonlAuditLog
from ai_alert_triage.ports.llm import LLMAuditEntry, LLMMessage


def entry() -> LLMAuditEntry:
    return LLMAuditEntry(
        timestamp=datetime(2026, 10, 20, tzinfo=UTC),
        alert_id=uuid4(),
        provider="openai",
        model="gpt-test",
        messages=(LLMMessage("user", "hello"),),
        output='{"severity": "low"}',
        input_tokens=10,
        output_tokens=5,
        cost_usd=0.0001,
        latency_ms=42,
        error=None,
    )


def test_appends_one_json_line_per_entry(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "audit.jsonl"
    log = JsonlAuditLog(path)

    first, second = entry(), entry()
    log.record(first)
    log.record(second)

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    parsed = json.loads(lines[0])
    assert parsed["alert_id"] == str(first.alert_id)
    assert parsed["messages"] == [{"role": "user", "content": "hello"}]
    assert parsed["cost_usd"] == 0.0001
