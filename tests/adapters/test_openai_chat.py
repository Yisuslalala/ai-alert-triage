from types import SimpleNamespace
from typing import Any

import httpx2
import openai
import pytest
from openai.types.chat import ChatCompletion

from ai_alert_triage.adapters.llm.openai_chat import OpenAIChatClient
from ai_alert_triage.ports.llm import LLMError, LLMMessage, LLMRequest

REQUEST = LLMRequest(
    messages=(LLMMessage("system", "sys"), LLMMessage("user", "usr")),
    schema_name="alert_triage",
    json_schema={"type": "object"},
)


def completion(content: str | None, refusal: str | None = None) -> ChatCompletion:
    return ChatCompletion.model_validate(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-test-2026-01-01",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": content, "refusal": refusal},
                }
            ],
            "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
        }
    )


class FakeSDK:
    def __init__(self, result: ChatCompletion | Exception) -> None:
        self.calls: list[dict[str, Any]] = []
        self._result = result
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> ChatCompletion:
        self.calls.append(kwargs)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def test_sends_strict_json_schema_and_maps_response() -> None:
    sdk = FakeSDK(completion('{"severity": "low", "summary": "ok"}'))

    response = OpenAIChatClient(sdk, "gpt-test").complete(REQUEST)

    call = sdk.calls[0]
    assert call["model"] == "gpt-test"
    assert call["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "usr"},
    ]
    assert call["response_format"]["json_schema"]["strict"] is True
    assert call["response_format"]["json_schema"]["name"] == "alert_triage"
    assert response.content == '{"severity": "low", "summary": "ok"}'
    assert response.model == "gpt-test-2026-01-01"
    assert (response.input_tokens, response.output_tokens) == (120, 30)


def test_refusal_raises_llm_error() -> None:
    sdk = FakeSDK(completion(None, refusal="I can't help with that"))
    with pytest.raises(LLMError, match="refused"):
        OpenAIChatClient(sdk, "gpt-test").complete(REQUEST)


def test_sdk_errors_become_llm_errors() -> None:
    request = httpx2.Request("POST", "https://api.openai.com/v1/chat/completions")
    sdk = FakeSDK(openai.APITimeoutError(request=request))
    with pytest.raises(LLMError, match="APITimeoutError"):
        OpenAIChatClient(sdk, "gpt-test").complete(REQUEST)


def test_provider_name_is_configurable() -> None:
    assert OpenAIChatClient(FakeSDK(completion("{}")), "dep", provider="azure").provider == "azure"
