"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """isrm runtime settings."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    openrouter_api_key: str
    openrouter_model: str = "anthropic/claude-3.5-sonnet"
    openrouter_max_tokens: int | None = None
    virustotal_api_key: str | None = None


def load_settings() -> Settings:
    """Load and return application settings."""
    return Settings()  # type: ignore[call-arg]
