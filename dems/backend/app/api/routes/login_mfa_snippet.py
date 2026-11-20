"""Admin-only TOTP enforcement snippet for POST /auth/login."""
from __future__ import annotations

from typing import Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Role, User
from app.services.mfa_service import consume_backup_code, is_admin_user, verify_totp_code


async def enforce_admin_mfa_if_required(
    db: AsyncSession,
    user: User,
    totp_code: str | None,
    backup_code: str | None,
) -> dict[str, Any]:
    if not is_admin_user(user.role) or user.role != Role.ADMIN or not getattr(user, "mfa_enabled", False):
        return {"session_mfa_verified": False}

    if verify_totp_code(getattr(user, "totp_secret", None), totp_code):
        return {"session_mfa_verified": True}

    if backup_code and hasattr(user, "mfa_backup_code_hashes"):
        ok, remaining = consume_backup_code(user.mfa_backup_code_hashes, backup_code)
        if ok:
            user.mfa_backup_code_hashes = remaining
            await db.commit()
            return {"session_mfa_verified": True}

    if not totp_code and not backup_code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin MFA code required. Enter your 6-digit authenticator code or a backup code.",
            headers={"X-MFA-Required": "totp"},
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid admin MFA code.",
        headers={"X-MFA-Required": "totp"},
    )
