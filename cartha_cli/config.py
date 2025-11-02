"""Runtime configuration for the Cartha CLI."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    verifier_url: str = Field("http://127.0.0.1:8000", alias="CARTHA_VERIFIER_URL")
    network: str = Field("finney", alias="CARTHA_NETWORK")
    netuid: int = Field(35, alias="CARTHA_NETUID")

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
