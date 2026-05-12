"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """isrm runtime settings."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    openrouter_api_key: str
    openrouter_model: str = "anthropic/claude-3.5-sonnet"
    openrouter_max_tokens: int | None = None
    virustotal_api_key: str | None = None
    tavily_api_key: str | None = None
    threat_history_model: str | None = None  # falls back to openrouter_model
    threat_history_max_tokens: int | None = None  # falls back to openrouter_max_tokens
    threat_history_max_searches: int = 8
    threat_history_max_results_per_search: int = 5
    threat_history_search_depth: str = "basic"  # "basic" or "advanced"


def load_settings() -> Settings:
    """Load and return application settings."""
    return Settings()  # type: ignore[call-arg]
