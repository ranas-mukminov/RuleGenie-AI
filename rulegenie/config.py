from functools import lru_cache
from typing import Optional

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application configuration sourced from environment."""

    database_url: str = Field(default="sqlite:///./rulegenie.db")
    environment: str = Field(default="dev")
    api_key: Optional[str] = Field(default=None, description="Optional API key for dev mode protection.")
    llm_provider: Optional[str] = Field(default=None)
    llm_api_key: Optional[str] = Field(default=None)

    model_config = {
        "env_prefix": "RULEGENIE_",
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()
