import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

Provider = Literal["keyword", "openai", "azure"]
_PROVIDERS = ("keyword", "openai", "azure")


class ConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Settings:
    llm_provider: Provider
    llm_model: str | None
    openai_api_key: str | None
    azure_endpoint: str | None
    azure_api_key: str | None
    azure_api_version: str | None
    price_input_per_million_usd: float | None
    price_output_per_million_usd: float | None
    audit_log_path: Path
    database_url: str | None
    auth_disabled: bool = False
    auth_issuer: str | None = None
    auth_audience: str | None = None
    auth_jwks_url: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> Settings:
        provider = env.get("LLM_PROVIDER", "keyword").lower()
        if provider not in _PROVIDERS:
            raise ConfigError(f"LLM_PROVIDER must be one of {_PROVIDERS}, got {provider!r}")

        settings = cls(
            llm_provider=cast(Provider, provider),
            llm_model=env.get("LLM_MODEL") or None,
            openai_api_key=env.get("OPENAI_API_KEY") or None,
            azure_endpoint=env.get("AZURE_OPENAI_ENDPOINT") or None,
            azure_api_key=env.get("AZURE_OPENAI_API_KEY") or None,
            azure_api_version=env.get("AZURE_OPENAI_API_VERSION") or None,
            price_input_per_million_usd=_optional_float(env, "LLM_PRICE_INPUT_PER_MILLION"),
            price_output_per_million_usd=_optional_float(env, "LLM_PRICE_OUTPUT_PER_MILLION"),
            audit_log_path=Path(env.get("AUDIT_LOG_PATH", "logs/llm_audit.jsonl")),
            database_url=env.get("DATABASE_URL") or None,
            auth_disabled=env.get("AUTH_DISABLED", "false").lower() == "true",
            auth_issuer=env.get("AUTH_ISSUER") or None,
            auth_audience=env.get("AUTH_AUDIENCE") or None,
            auth_jwks_url=env.get("AUTH_JWKS_URL") or None,
        )
        settings._validate()
        return settings

    def _validate(self) -> None:
        required: dict[str, object] = {}
        if self.llm_provider == "openai":
            required = {"LLM_MODEL": self.llm_model, "OPENAI_API_KEY": self.openai_api_key}
        elif self.llm_provider == "azure":
            required = {
                "LLM_MODEL": self.llm_model,
                "AZURE_OPENAI_ENDPOINT": self.azure_endpoint,
                "AZURE_OPENAI_API_KEY": self.azure_api_key,
                "AZURE_OPENAI_API_VERSION": self.azure_api_version,
            }
        if not self.auth_disabled:
            # Secure by default: running without auth has to be an explicit choice.
            required |= {
                "AUTH_ISSUER": self.auth_issuer,
                "AUTH_AUDIENCE": self.auth_audience,
                "AUTH_JWKS_URL": self.auth_jwks_url,
            }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ConfigError(
                f"missing required settings: {', '.join(missing)}"
                " (set AUTH_DISABLED=true to run without authentication)"
            )


def _optional_float(env: Mapping[str, str], key: str) -> float | None:
    value = env.get(key)
    if not value:
        return None
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a number, got {value!r}") from exc
