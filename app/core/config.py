import base64
import binascii
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["dev", "prod"] = "dev"
    database_url: str = "sqlite+aiosqlite:///./data/dev.db"
    master_key: SecretStr
    session_cookie_name: str = "session"
    session_ttl_seconds: int = Field(default=8 * 60 * 60, gt=0)
    upload_dir: Path = Path("data/uploads")
    cors_origins: str = ""
    log_level: str = "INFO"
    rate_limit_enabled: bool = True
    rate_limit_default: str = "100/minute"
    rate_limit_auth: str = "10/minute"

    @field_validator("master_key")
    @classmethod
    def validate_master_key(cls, value: SecretStr) -> SecretStr:
        encoded = value.get_secret_value()
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("MASTER_KEY must be base64 encoded") from exc
        if len(decoded) != 32:
            raise ValueError("MASTER_KEY must decode to 32 bytes")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
