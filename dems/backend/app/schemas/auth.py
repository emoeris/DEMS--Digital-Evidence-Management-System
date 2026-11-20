from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.users import UserOut


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    totp_code: str | None = Field(default=None, max_length=16)
    backup_code: str | None = Field(default=None, max_length=16)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool = False
    mfa_enabled: bool = False


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str = Field(min_length=10, max_length=4096)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class MFAEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=16)


class MFAVerifyResponse(BaseModel):
    mfa_enabled: bool
    access_token: str
    backup_codes: list[str] = Field(default_factory=list, description="Shown once, at first enablement.")


class MeResponse(BaseModel):
    user: UserOut
    session_mfa_verified: bool
