import json
from datetime import UTC, datetime
from typing import Any

import pytest

from ai_alert_triage.adapters.context.okta import MockOktaIdentitySource
from ai_alert_triage.adapters.context.sentinelone import MockSentinelOneEndpointSource
from ai_alert_triage.adapters.context.zscaler import MockZscalerNetworkSource
from ai_alert_triage.adapters.investigation.llm_agent import (
    LLMInvestigationAgent,
    extract_entities,
)
from ai_alert_triage.adapters.redaction.regex import RegexRedactor
from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.investigation import InvestigationError
from ai_alert_triage.ports.llm import LLMAuditEntry, LLMError, LLMRequest, LLMResponse

NOW = datetime(2026, 10, 20, 8, 5, tzinfo=UTC)
EMAIL = "j.doe@example.com"


class ScriptedLLMClient:
    """Returns the scripted replies in order, recording every request."""

    provider = "fake"

    def __init__(self, *replies: str | LLMError) -> None:
        self._replies = list(replies)
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        reply = self._replies.pop(0)
        if isinstance(reply, LLMError):
            raise reply
        return LLMResponse(reply, "fake-model-2026", input_tokens=500, output_tokens=50)


class ListAuditLog:
    def __init__(self) -> None:
        self.entries: list[LLMAuditEntry] = []

    def record(self, entry: LLMAuditEntry) -> None:
        self.entries.append(entry)


def call(action: str, entity: str) -> str:
    return json.dumps({"action": action, "entity": entity, "report": None})


def finish(techniques: list[str] | None = None, summary: str = "Account takeover.") -> str:
    report = {
        "summary": summary,
        "techniques": techniques or [],
        "next_steps": ["Reset the user's credentials.", "Isolate WS-0142."],
    }
    return json.dumps({"action": "finish", "entity": None, "report": report})


def make_alert() -> Alert:
    return Alert(
        source="sentinelone",
        title="Malicious PowerShell after suspicious sign-in",
        description=f"User {EMAIL} ran an encoded script.",
        received_at=NOW,
        raw_payload={"user": EMAIL, "hostname": "WS-0142", "url": "update-microsoft-cdn.com"},
    )


def make_agent(
    client: ScriptedLLMClient, max_steps: int = 8
) -> tuple[LLMInvestigationAgent, ListAuditLog]:
    audit = ListAuditLog()
    agent = LLMInvestigationAgent(
        client=client,
        audit_log=audit,
        redactor=RegexRedactor(),
        identity=MockOktaIdentitySource(),
        endpoint=MockSentinelOneEndpointSource(),
        network=MockZscalerNetworkSource(),
        max_steps=max_steps,
        clock=lambda: NOW,
        nonce=lambda: "n0nce",
    )
    return agent, audit


def all_prompt_text(client: ScriptedLLMClient) -> str:
    return "\n".join(m.content for r in client.requests for m in r.messages)


def test_investigates_with_tools_and_writes_report() -> None:
    client = ScriptedLLMClient(
        call("sentinelone_get_threats", "host_1"),
        call("okta_get_system_log", "user_1"),
        finish(["T1059.001", "T1621", "T1059.001"]),
    )
    agent, audit = make_agent(client)

    report = agent.investigate(make_alert())

    assert [e.query for e in report.evidence] == [
        "sentinelone_get_threats(host_1)",
        "okta_get_system_log(user_1)",
    ]
    assert report.evidence[0].data[0]["threatInfo"]["threatName"] == "invoice_0923.ps1"
    assert [t.id for t in report.techniques] == ["T1059.001", "T1621"]
    assert report.techniques[0].tactic == "Execution"
    assert report.next_steps == ("Reset the user's credentials.", "Isolate WS-0142.")
    assert report.model == "fake-model-2026"
    assert len(audit.entries) == 3


def test_tool_results_are_fed_back_as_tagged_untrusted_data() -> None:
    client = ScriptedLLMClient(call("zscaler_url_lookup", "url_1"), finish())
    agent, _ = make_agent(client)

    agent.investigate(make_alert())

    last_message = client.requests[1].messages[-1].content
    assert last_message.startswith("<tool-result-n0nce>")
    assert "MALWARE_SITE" in last_message


def test_raw_pii_never_reaches_the_llm_or_the_report() -> None:
    client = ScriptedLLMClient(
        call("okta_get_user", "user_1"), call("okta_get_system_log", "user_1"), finish()
    )
    agent, _ = make_agent(client)

    report = agent.investigate(make_alert())

    assert EMAIL not in all_prompt_text(client)
    assert EMAIL not in json.dumps([e.data for e in report.evidence])
    assert "[REDACTED_EMAIL]" in all_prompt_text(client)


def test_the_last_step_can_only_finish() -> None:
    client = ScriptedLLMClient(call("okta_get_user", "user_1"), finish())
    agent, _ = make_agent(client, max_steps=2)

    agent.investigate(make_alert())

    def actions(request: LLMRequest) -> Any:
        return request.json_schema["properties"]["action"]["enum"]

    assert "okta_get_user" in actions(client.requests[0])
    assert actions(client.requests[1]) == ["finish"]


@pytest.mark.parametrize(
    "bad_call",
    [
        call("okta_get_user", "host_1"),  # wrong entity kind
        call("okta_get_user", "user_99"),  # handle not in the alert
        call("okta_get_user", "attacker@evil.com"),  # raw value instead of a handle
    ],
)
def test_lookups_are_limited_to_entities_in_the_alert(bad_call: str) -> None:
    client = ScriptedLLMClient(bad_call, finish())
    agent, _ = make_agent(client)

    report = agent.investigate(make_alert())

    assert report.evidence == ()
    assert '"error"' in client.requests[1].messages[-1].content


@pytest.mark.parametrize(
    "replies",
    [
        ("not json",),
        (json.dumps({"action": "suspend_user", "entity": "user_1", "report": None}),),
        (json.dumps({"action": "finish", "entity": None, "report": None}),),
        (LLMError("timeout"),),
    ],
)
def test_failures_raise_investigation_error(replies: tuple[str | LLMError, ...]) -> None:
    agent, audit = make_agent(ScriptedLLMClient(*replies))

    with pytest.raises(InvestigationError):
        agent.investigate(make_alert())
    assert len(audit.entries) == 1


def test_extract_entities_maps_handles_to_payload_values() -> None:
    alert = Alert(
        "proxy",
        "Blocked download",
        "",
        NOW,
        raw_payload={"username": ["a@x.com", "b@x.com", "a@x.com"], "domain": "evil.test"},
    )

    entities = extract_entities(alert)

    assert {handle: e.value for handle, e in entities.items()} == {
        "user_1": "a@x.com",
        "user_2": "b@x.com",
        "url_1": "evil.test",
    }


def test_mock_sources_follow_vendor_shapes() -> None:
    assert MockOktaIdentitySource().get_user("J.Doe@Example.com") is not None
    assert MockSentinelOneEndpointSource().get_agent("ws-0142")["computerName"] == "WS-0142"  # type: ignore[index]
    unknown = MockZscalerNetworkSource().lookup_url("https://unknown.example/path")
    assert unknown["urlClassifications"] == ["MISCELLANEOUS_OR_UNKNOWN"]
