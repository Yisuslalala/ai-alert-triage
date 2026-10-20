from pathlib import Path

import pytest

from ai_alert_triage.config import ConfigError, Settings


def test_defaults_to_keyword_provider() -> None:
    settings = Settings.from_env({})
    assert settings.llm_provider == "keyword"
    assert settings.audit_log_path == Path("logs/llm_audit.jsonl")


def test_openai_requires_model_and_key() -> None:
    with pytest.raises(ConfigError, match="LLM_MODEL, OPENAI_API_KEY"):
        Settings.from_env({"LLM_PROVIDER": "openai"})


def test_azure_requires_endpoint_key_and_version() -> None:
    with pytest.raises(ConfigError, match="AZURE_OPENAI_ENDPOINT"):
        Settings.from_env({"LLM_PROVIDER": "azure", "LLM_MODEL": "my-deployment"})


def test_valid_openai_settings() -> None:
    settings = Settings.from_env(
        {
            "LLM_PROVIDER": "OpenAI",
            "LLM_MODEL": "gpt-test",
            "OPENAI_API_KEY": "sk-test",
            "LLM_PRICE_INPUT_PER_MILLION": "0.4",
            "LLM_PRICE_OUTPUT_PER_MILLION": "1.6",
        }
    )
    assert settings.llm_provider == "openai"
    assert settings.price_input_per_million_usd == 0.4


@pytest.mark.parametrize(
    "env",
    [{"LLM_PROVIDER": "gemini"}, {"LLM_PRICE_INPUT_PER_MILLION": "cheap"}],
)
def test_invalid_values_are_rejected(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env)
