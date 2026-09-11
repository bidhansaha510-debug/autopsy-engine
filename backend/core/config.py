from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Infrastructure Autopsy"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"  # "production", "demo", "test"
    AUTO_BOOTSTRAP_DEMO: bool = False
    LOG_LEVEL: str = "INFO"

    # Database: Supports SQLite for zero-dependency local forensic runs,
    # or PostgreSQL via postgresql+psycopg2://user:pass@host:5432/autopsy
    DATABASE_URL: str = "sqlite:///./autopsy.db"
    ECHO_SQL: bool = False

    # Ollama AI Configuration
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    OLLAMA_TIMEOUT_SECONDS: float = 45.0

    # Security & Guardrails
    READ_ONLY_BY_DEFAULT: bool = True
    ALLOW_COMMAND_EXECUTION: bool = False
    CORS_ORIGINS: List[str] = ["*"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
