"""Application settings (Pydantic Settings, loaded from environment / .env)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER = re.compile(r"change[-_ ]?me", re.IGNORECASE)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- General ---------------------------------------------------------
    app_name: str = "DEMS"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False

    # --- Secrets ---------------------------------------------------------
    secret_key: SecretStr
    kek_passphrase: SecretStr | None = None

    # --- Storage ---------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./dems.db"
    vault_path: Path = Path("./vault")
    key_config_path: Path = Path("./keyconfig.json")
    upload_max_bytes: int = Field(2 * 1024**3, ge=1)
    chunk_size: int = Field(1024 * 1024, ge=64 * 1024, le=16 * 1024 * 1024)

    # --- Tokens ----------------------------------------------------------
    access_token_ttl: int = Field(900, ge=60, le=3600)
    refresh_token_ttl: int = Field(604800, ge=3600, le=30 * 86400)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    jwt_issuer: str = "dems"
    jwt_audience: str = "dems-api"

    # --- CORS ------------------------------------------------------------
    cors_origins: str = "https://localhost:5173,http://localhost:5173"

    # --- KEK derivation (Argon2id) --------------------------------------
    kdf_time_cost: int = Field(3, ge=1)
    kdf_memory_kib: int = Field(262144, ge=8)
    kdf_parallelism: int = Field(4, ge=1, le=64)

    # --- Password hashing (Argon2id) ------------------------------------
    password_time_cost: int = Field(3, ge=1)
    password_memory_kib: int = Field(65536, ge=8)
    password_parallelism: int = Field(4, ge=1, le=64)
    common_passwords_path: Path | None = None

    # --- Auth policy ------------------------------------------------------
    max_login_attempts: int = Field(5, ge=3, le=20)
    lockout_base_seconds: int = Field(900, ge=1)
    lockout_max_seconds: int = Field(86400, ge=1)
    require_admin_mfa: bool = False

    # --- Evidence ingestion ------------------------------------------------
    # Comma separated; "type/*" wildcards allowed. Evidence is never executed or rendered.
    allowed_mime_types: str = (
        "image/*,audio/*,video/*,text/*,application/pdf,application/json,application/xml,"
        "application/zip,application/gzip,application/x-tar,application/x-7z-compressed,"
        "application/x-rar,application/vnd.rar,application/x-bzip2,application/x-xz,"
        "application/msword,application/vnd.ms-excel,application/vnd.ms-powerpoint,"
        "application/vnd.openxmlformats-officedocument.*,application/vnd.oasis.opendocument.*,"
        "application/vnd.sqlite3,application/x-sqlite3,application/vnd.tcpdump.capture,"
        "application/x-dosexec,application/vnd.microsoft.portable-executable,application/x-msdownload,application/x-executable,application/x-sharedlib,"
        "application/x-mach-binary,application/java-archive,application/vnd.android.package-archive,"
        "message/rfc822,application/octet-stream"
    )
    verify_before_download: bool = True

    # ---------------------------------------------------------------------
    @field_validator("secret_key")
    @classmethod
    def _check_secret_key(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value()
        if len(raw) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        if _PLACEHOLDER.search(raw):
            raise ValueError("SECRET_KEY still contains the example placeholder")
        return v

    @field_validator("kek_passphrase")
    @classmethod
    def _check_kek(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None or v.get_secret_value() == "":
            return None
        raw = v.get_secret_value()
        if len(raw) < 12:
            raise ValueError("KEK_PASSPHRASE must be at least 12 characters")
        if _PLACEHOLDER.search(raw):
            raise ValueError("KEK_PASSPHRASE still contains the example placeholder")
        return v

    @field_validator("database_url")
    @classmethod
    def _check_db_url(cls, v: str) -> str:
        if "+aiosqlite" not in v and "+asyncpg" not in v:
            raise ValueError("DATABASE_URL must use an async driver (aiosqlite or asyncpg)")
        return v

    @field_validator("cors_origins")
    @classmethod
    def _check_cors(cls, v: str) -> str:
        origins = [o.strip() for o in v.split(",") if o.strip()]
        if not origins:
            raise ValueError("CORS_ORIGINS must list at least one origin")
        for o in origins:
            if o == "*" or not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", o):
                raise ValueError(f"Invalid CORS origin: {o!r} (no wildcards, no paths)")
        return ",".join(origins)

    @field_validator("vault_path", "key_config_path")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return v.expanduser()

    @model_validator(mode="after")
    def _production_rules(self) -> "Settings":
        if self.environment == "production":
            if self.debug:
                raise ValueError("DEBUG must be false in production")
            if any(not o.startswith("https://") for o in self.cors_origin_list):
                raise ValueError("Production CORS origins must use https")
            if self.kdf_memory_kib < 131072 or self.password_memory_kib < 19456:
                raise ValueError("Argon2 memory cost too low for production")
            if not self.require_admin_mfa:
                raise ValueError("REQUIRE_ADMIN_MFA must be true in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o for o in self.cors_origins.split(",") if o]

    @property
    def allowed_mime_list(self) -> list[str]:
        return [m.strip().lower() for m in self.allowed_mime_types.split(",") if m.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
