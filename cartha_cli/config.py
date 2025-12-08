"""Runtime configuration for the Cartha CLI."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    verifier_url: str = Field(
        "https://cartha-verifier-826542474079.us-central1.run.app", alias="CARTHA_VERIFIER_URL"
    )
    network: str = Field("finney", alias="CARTHA_NETWORK")
    netuid: int = Field(35, alias="CARTHA_NETUID")
    evm_private_key: str | None = Field(None, alias="CARTHA_EVM_PK")
    # Retry configuration
    retry_max_attempts: int = Field(3, alias="CARTHA_RETRY_MAX_ATTEMPTS")
    retry_backoff_factor: float = Field(1.5, alias="CARTHA_RETRY_BACKOFF_FACTOR")
    # Note: retry_on_status cannot be set via env var easily (would need JSON parsing)
    # For now, it's hardcoded but can be overridden programmatically
    retry_on_status: list[int] = Field(default_factory=lambda: [500, 502, 503, 504])

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "env_nested_delimiter": "__",
    }


@lru_cache(maxsize=1)
def get_settings(**overrides: Any) -> Settings:
    return Settings(**overrides)


settings = get_settings()

__all__ = ["settings", "Settings", "get_settings"]
