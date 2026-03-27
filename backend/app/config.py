from __future__ import annotations

import os
from dataclasses import dataclass


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_list(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    environment: str
    database_url: str
    require_api_key: bool
    api_key: str | None
    enable_demo_routes: bool
    allowed_origins: list[str]
    correlation_window_minutes: int
    ollama_enabled: bool
    ollama_host: str
    ollama_model: str
    ollama_timeout_seconds: int
    ransomware_live_enabled: bool
    ransomware_live_base_url: str
    ransomware_live_timeout_seconds: int


settings = Settings(
    app_name=os.getenv("ATIRF_APP_NAME", "ATIRF Platform"),
    app_version=os.getenv("ATIRF_APP_VERSION", "1.1.0"),
    environment=os.getenv("ATIRF_ENV", "development"),
    database_url=os.getenv("ATIRF_DATABASE_URL", "sqlite:///./atirf.db"),
    require_api_key=_get_bool("ATIRF_REQUIRE_API_KEY", False),
    api_key=os.getenv("ATIRF_API_KEY"),
    enable_demo_routes=_get_bool("ATIRF_ENABLE_DEMO_ROUTES", True),
    allowed_origins=_get_list("ATIRF_ALLOWED_ORIGINS", "*"),
    correlation_window_minutes=max(1, int(os.getenv("ATIRF_CORRELATION_WINDOW_MINUTES", "240"))),
    ollama_enabled=_get_bool("ATIRF_OLLAMA_ENABLED", False),
    ollama_host=os.getenv("ATIRF_OLLAMA_HOST", "http://127.0.0.1:11434"),
    ollama_model=os.getenv("ATIRF_OLLAMA_MODEL", "llama3.1:8b"),
    ollama_timeout_seconds=max(5, int(os.getenv("ATIRF_OLLAMA_TIMEOUT_SECONDS", "90"))),
    ransomware_live_enabled=_get_bool("ATIRF_RANSOMWARE_LIVE_ENABLED", False),
    ransomware_live_base_url=os.getenv("ATIRF_RANSOMWARE_LIVE_BASE_URL", "https://api.ransomware.live/v2"),
    ransomware_live_timeout_seconds=max(5, int(os.getenv("ATIRF_RANSOMWARE_LIVE_TIMEOUT_SECONDS", "30"))),
)
