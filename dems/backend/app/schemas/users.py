from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import Role
from app.schemas.common import ORMModel

_USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
_EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,185}\.[A-Za-z]{2,}")


class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=128, description="Temporary password; must be changed at first login.")
    role: Role

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        v = v.lower()
        if not _USERNAME_RE.fullmatch(v):
            raise ValueError("username must be 3-64 characters: letters, digits, '.', '_' or '-'")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not _EMAIL_RE.fullmatch(v):
            raise ValueError("invalid email address")
        return v.lower()


class UserOut(ORMModel):
    id: uuid.UUID
    username: str
    email: str
    role: Role
    is_active: bool
    must_change_password: bool
    mfa_enabled: bool
    created_at: datetime
    last_login_at: datetime | None = None
