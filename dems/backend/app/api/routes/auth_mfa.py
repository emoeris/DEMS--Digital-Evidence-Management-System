"""FastAPI router for admin-only TOTP MFA enrollment and verification."""
from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import DbDep, get_current_user
from app.db.models import Role, User
from app.services.mfa_service import (
    build_provisioning_uri,
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    hash_backup_code,
    is_admin_user,
    verify_totp_code,
)

router = APIRouter(prefix="/auth/mfa", tags=["auth-mfa"])


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaVerifySetupRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class MfaVerifySetupResponse(BaseModel):
    mfa_enabled: bool
    backup_codes: list[str]


class MfaDisableRequest(BaseModel):
    code: str = Field(min_length=4, max_length=24)


def _require_admin(user: User) -> User:
    if not is_admin_user(user.role) or user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA is currently enabled for admin accounts only.",
        )
    return user


@router.post("/setup", response_model=MfaSetupResponse)
async def setup_admin_mfa(
    db: DbDep,
    current_user: Annotated[User, Depends(get_current_user)],
) -> MfaSetupResponse:
    admin = _require_admin(current_user)
    secret = generate_totp_secret()
    admin.totp_secret = secret
    admin.mfa_enabled = False
    await db.commit()
    uri = build_provisioning_uri(secret=secret, username=admin.username, issuer="DEMS Local")
    return MfaSetupResponse(secret=secret, provisioning_uri=uri)


@router.post("/verify-setup", response_model=MfaVerifySetupResponse)
async def verify_admin_mfa_setup(
    body: MfaVerifySetupRequest,
    db: DbDep,
    current_user: Annotated[User, Depends(get_current_user)],
) -> MfaVerifySetupResponse:
    admin = _require_admin(current_user)
    if not verify_totp_code(admin.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 6-digit authenticator code.")

    raw_codes = generate_backup_codes(8)
    admin.mfa_enabled = True
    if hasattr(admin, "mfa_backup_code_hashes"):
        admin.mfa_backup_code_hashes = [hash_backup_code(c) for c in raw_codes]
    await db.commit()
    return MfaVerifySetupResponse(mfa_enabled=True, backup_codes=raw_codes)


@router.post("/disable")
async def disable_admin_mfa(
    body: MfaDisableRequest,
    db: DbDep,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, bool]:
    admin = _require_admin(current_user)
    totp_ok = verify_totp_code(admin.totp_secret, body.code)
    backup_ok = False
    if not totp_ok and hasattr(admin, "mfa_backup_code_hashes"):
        ok, remaining = consume_backup_code(admin.mfa_backup_code_hashes, body.code)
        if ok:
            backup_ok = True
            admin.mfa_backup_code_hashes = remaining

    if not (totp_ok or backup_ok):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid authenticator or backup code.")

    admin.mfa_enabled = False
    admin.totp_secret = None
    await db.commit()
    return {"mfa_enabled": False}
