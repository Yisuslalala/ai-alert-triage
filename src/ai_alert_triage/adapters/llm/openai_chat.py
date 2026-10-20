from typing import Any

import openai

from ai_alert_triage.ports.llm import LLMError, LLMRequest, LLMResponse


class OpenAIChatClient:
    """LLMClient over the Chat Completions API with strict structured output.

    Works for both OpenAI and Azure OpenAI: pass an ``openai.OpenAI`` or
    ``openai.AzureOpenAI`` client. On Azure, ``model`` is the deployment name.
    """

    def __init__(self, client: Any, model: str, provider: str = "openai") -> None:
        self._client = client
        self._model = model
        self._provider = provider

    @property
    def provider(self) -> str:
        return self._provider

    def complete(self, request: LLMRequest) -> LLMResponse:
        messages = [
            {"role": message.role, "content": message.content}
            for message in request.messages
        ]
        try:
            completion = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": request.schema_name,
                        "schema": request.json_schema,
                        "strict": True,
                    },
                },
            )
        except openai.OpenAIError as exc:
            raise LLMError(f"{type(exc).__name__}: {exc}") from exc

        if not completion.choices:
            raise LLMError("response has no choices")
        message = completion.choices[0].message
        if message.refusal:
            raise LLMError(f"model refused: {message.refusal}")
        if not message.content:
            raise LLMError("response has no content")

        usage = completion.usage
        return LLMResponse(
            content=message.content,
            model=completion.model,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )
