"""Authentication and session management.

Every state change and its audit entry are committed in one transaction. Argon2 work
runs in a worker thread so it never blocks the event loop.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    TokenClaims, TokenError, authenticate_password, create_access_token, create_refresh_token,
    decode_token, decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes, generate_totp_secret,
    hash_password, hash_token, totp_provisioning_uri, validate_password_policy, verify_backup_code,
    verify_password, verify_totp,
)
from app.core.crypto import constant_time_equals
from app.db.models import (
    AuditAction, AuthSession, Outcome, RefreshToken, RefreshTokenStatus, RevokedAccessToken, Role, User, utcnow,
)
from app.db.session import begin_write
from app.services import audit_service
from app.services.context import RequestContext
from app.services.errors import ServiceError, bad_request, conflict, unauthorized

GENERIC_LOGIN_ERROR = "Invalid credentials or account temporarily locked."
PASSWORD_HISTORY = 5


@dataclass(frozen=True)
class TokenBundle:
    access_token: str
    refresh_token: str
    expires_in: int
    must_change_password: bool
    mfa_enabled: bool


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
async def _get_user_by_username(db: AsyncSession, username: str) -> User | None:
    return (await db.execute(select(User).where(User.username == username.strip().lower()))).scalar_one_or_none()


def _lockout_seconds(level: int) -> int:
    s = get_settings()
    return min(s.lockout_base_seconds * (2 ** max(level - 1, 0)), s.lockout_max_seconds)


async def _register_failure(
    db: AsyncSession,
    user: User | None,
    *,
    username: str,
    ctx: RequestContext,
    reason: str,
    action: AuditAction = AuditAction.LOGIN_FAILURE,
    message: str = GENERIC_LOGIN_ERROR,
) -> ServiceError:
    """Count a failed attempt, lock the account at the threshold, audit, commit. Returns the error to raise."""
    await begin_write(db)
    locked_until: datetime | None = None
    if user is not None:
        await db.refresh(user)  # re-read under the write lock so concurrent attempts are all counted
        user.failed_login_count += 1
        if user.failed_login_count >= get_settings().max_login_attempts:
            user.lockout_level += 1
            user.failed_login_count = 0
            locked_until = utcnow() + timedelta(seconds=_lockout_seconds(user.lockout_level))
            user.locked_until = locked_until
    await audit_service.record(
        db, action=action, outcome=Outcome.FAILURE, ctx=ctx, actor_id=user.id if user else None,
        username_attempted=username, resource_type="user", resource_id=user.id if user else None,
        details={"reason": reason},
    )
    if locked_until is not None and user is not None:
        await audit_service.record(
            db, action=AuditAction.LOCKOUT, outcome=Outcome.DENIED, ctx=ctx, actor_id=user.id,
            resource_type="user", resource_id=user.id,
            details={"locked_until": locked_until.isoformat(), "level": user.lockout_level},
        )
    await db.commit()
    return unauthorized("invalid_credentials", message)


async def _issue_tokens(db: AsyncSession, user: User, ctx: RequestContext, *, mfa_verified: bool) -> TokenBundle:
    s = get_settings()
    now = utcnow()
    session = AuthSession(
        id=uuid.uuid4(), user_id=user.id, expires_at=now + timedelta(seconds=s.refresh_token_ttl),
        ip=ctx.ip, user_agent_hash=ctx.user_agent_hash, mfa_verified=mfa_verified,
    )
    db.add(session)
    await db.flush()
    refresh = create_refresh_token(user_id=user.id, session_id=session.id)
    db.add(
        RefreshToken(
            session_id=session.id, jti=refresh.jti, token_hash=hash_token(refresh.token),
            expires_at=refresh.expires_at,
        )
    )
    access = create_access_token(user_id=user.id, role=user.role.value, session_id=session.id, mfa_verified=mfa_verified)
    await db.flush()
    return TokenBundle(access.token, refresh.token, s.access_token_ttl, user.must_change_password, user.mfa_enabled)


async def _revoke_session(db: AsyncSession, session: AuthSession, reason: str) -> None:
    now = utcnow()
    session.revoked_at = session.revoked_at or now
    session.revoked_reason = session.revoked_reason or reason
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.session_id == session.id, RefreshToken.status == RefreshTokenStatus.ACTIVE)
        .values(status=RefreshTokenStatus.REVOKED, revoked_reason=reason)
    )


# --------------------------------------------------------------------------
# registration (admin only; enforced by the route guard)
# --------------------------------------------------------------------------
async def register_user(
    db: AsyncSession, *, admin: User, username: str, email: str, password: str, role: Role, ctx: RequestContext
) -> User:
    username, email = username.strip().lower(), email.strip().lower()
    policy = validate_password_policy(password, username=username, email=email)
    if not policy.valid:
        raise bad_request("weak_password", " ".join(policy.errors), 422)
    pw_hash = await asyncio.to_thread(hash_password, password)

    await begin_write(db)
    clash = await db.execute(select(User.id).where((User.username == username) | (User.email == email)))
    if clash.first() is not None:
        raise conflict("user_exists", "A user with that username or email already exists.")
    user = User(
        username=username, email=email, password_hash=pw_hash, role=role, must_change_password=True,
        password_history=[pw_hash], password_changed_at=utcnow(), created_by=admin.id,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise conflict("user_exists", "A user with that username or email already exists.") from None
    await audit_service.record(
        db, action=AuditAction.USER_CREATE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=admin.id,
        resource_type="user", resource_id=user.id, details={"username": username, "role": role.value},
    )
    await db.commit()
    return user


# --------------------------------------------------------------------------
# login
# --------------------------------------------------------------------------
async def login(
    db: AsyncSession, *, username: str, password: str, totp_code: str | None, backup_code: str | None,
    ctx: RequestContext,
) -> TokenBundle:
    user = await _get_user_by_username(db, username)
    now = utcnow()

    if user is not None and user.locked_until is not None and user.locked_until > now:
        await asyncio.to_thread(authenticate_password, password, None)  # equalise timing
        await begin_write(db)
        await audit_service.record(
            db, action=AuditAction.LOGIN_FAILURE, outcome=Outcome.DENIED, ctx=ctx, actor_id=user.id,
            username_attempted=username, resource_type="user", resource_id=user.id, details={"reason": "locked"},
        )
        await db.commit()
        raise unauthorized("invalid_credentials", GENERIC_LOGIN_ERROR)

    ok, needs_rehash = await asyncio.to_thread(authenticate_password, password, user.password_hash if user else None)
    if not ok or user is None:
        raise await _register_failure(db, user, username=username, ctx=ctx, reason="bad_password")
    if not user.is_active:
        raise await _register_failure(db, user, username=username, ctx=ctx, reason="inactive")

    mfa_counter: int | None = None
    used_backup_index: int | None = None
    if user.mfa_enabled:
        if totp_code:
            secret = decrypt_totp_secret(user.mfa_secret_enc or b"")
            mfa_counter = verify_totp(secret, totp_code, last_used_counter=user.mfa_last_counter)
            mfa_ok = mfa_counter is not None
        elif backup_code:
            used_backup_index = await asyncio.to_thread(verify_backup_code, backup_code, list(user.backup_codes_hash))
            mfa_ok = used_backup_index is not None
        else:
            raise unauthorized("mfa_required", "A verification code is required.")
        if not mfa_ok:
            raise await _register_failure(
                db, user, username=username, ctx=ctx, reason="bad_mfa_code", action=AuditAction.MFA_FAILURE
            )

    new_hash = await asyncio.to_thread(hash_password, password) if needs_rehash else None

    await begin_write(db)
    await db.refresh(user)
    if mfa_counter is not None and mfa_counter <= user.mfa_last_counter:  # replay lost a race
        raise await _register_failure(
            db, user, username=username, ctx=ctx, reason="mfa_replay", action=AuditAction.MFA_FAILURE
        )
    if mfa_counter is not None:
        user.mfa_last_counter = mfa_counter
    if used_backup_index is not None:
        user.backup_codes_hash = [h for i, h in enumerate(user.backup_codes_hash) if i != used_backup_index]
    if new_hash:
        user.password_hash = new_hash
    user.failed_login_count = 0
    user.lockout_level = 0
    user.locked_until = None
    user.last_login_at = utcnow()

    bundle = await _issue_tokens(db, user, ctx, mfa_verified=user.mfa_enabled)
    await audit_service.record(
        db, action=AuditAction.LOGIN_SUCCESS, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        username_attempted=user.username, resource_type="user", resource_id=user.id,
        details={"mfa": user.mfa_enabled, "backup_code_used": used_backup_index is not None},
    )
    await db.commit()
    return bundle


# --------------------------------------------------------------------------
# refresh (single-use rotation with reuse detection)
# --------------------------------------------------------------------------
async def refresh(db: AsyncSession, *, refresh_token: str, ctx: RequestContext) -> TokenBundle:
    try:
        claims = decode_token(refresh_token, expected_type="refresh")
    except TokenError:
        raise unauthorized("invalid_token", "Invalid or expired refresh token.") from None

    await begin_write(db)
    row = (
        await db.execute(select(RefreshToken).where(RefreshToken.jti == claims.jti).with_for_update())
    ).scalar_one_or_none()
    if row is None or not constant_time_equals(row.token_hash, hash_token(refresh_token)):
        await db.rollback()
        raise unauthorized("invalid_token", "Invalid or expired refresh token.")

    session = await db.get(AuthSession, row.session_id)
    if session is None or str(session.id) != claims.session_id:
        await db.rollback()
        raise unauthorized("invalid_token", "Invalid or expired refresh token.")

    if row.status != RefreshTokenStatus.ACTIVE:
        if row.status == RefreshTokenStatus.ROTATED:  # a used token came back: assume theft, kill the family
            await _revoke_session(db, session, "reuse_detected")
            await audit_service.record(
                db, action=AuditAction.TOKEN_REUSE_DETECTED, outcome=Outcome.DENIED, ctx=ctx,
                actor_id=session.user_id, resource_type="session", resource_id=session.id,
                details={"jti": row.jti},
            )
            await db.commit()
        else:
            await db.rollback()
        raise unauthorized("invalid_token", "Invalid or expired refresh token.")

    now = utcnow()
    user = await db.get(User, session.user_id)
    if session.revoked_at is not None or session.expires_at <= now or row.expires_at <= now or user is None or not user.is_active:
        await db.rollback()
        raise unauthorized("invalid_token", "Invalid or expired refresh token.")

    new_refresh = create_refresh_token(user_id=user.id, session_id=session.id)
    new_row = RefreshToken(
        session_id=session.id, jti=new_refresh.jti, token_hash=hash_token(new_refresh.token),
        expires_at=new_refresh.expires_at,
    )
    db.add(new_row)
    await db.flush()
    row.status = RefreshTokenStatus.ROTATED
    row.used_at = now
    row.replaced_by_id = new_row.id
    session.last_seen_at = now
    access = create_access_token(
        user_id=user.id, role=user.role.value, session_id=session.id, mfa_verified=session.mfa_verified
    )
    await audit_service.record(
        db, action=AuditAction.TOKEN_REFRESH, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="session", resource_id=session.id,
    )
    await db.commit()
    return TokenBundle(
        access.token, new_refresh.token, get_settings().access_token_ttl, user.must_change_password, user.mfa_enabled
    )


# --------------------------------------------------------------------------
# logout
# --------------------------------------------------------------------------
async def logout(db: AsyncSession, *, user: User, claims: TokenClaims, ctx: RequestContext) -> None:
    await begin_write(db)
    session = await db.get(AuthSession, uuid.UUID(claims.session_id))
    if session is not None:
        await _revoke_session(db, session, "logout")
    if await db.get(RevokedAccessToken, claims.jti) is None:
        db.add(RevokedAccessToken(jti=claims.jti, user_id=user.id, expires_at=claims.expires_at, reason="logout"))
    await audit_service.record(
        db, action=AuditAction.LOGOUT, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="session", resource_id=session.id if session else None,
    )
    await db.commit()


# --------------------------------------------------------------------------
# password change
# --------------------------------------------------------------------------
async def change_password(
    db: AsyncSession, *, user: User, claims: TokenClaims, current_password: str, new_password: str, ctx: RequestContext
) -> None:
    valid = await asyncio.to_thread(verify_password, current_password, user.password_hash)
    if not valid:
        raise await _register_failure(
            db, user, username=user.username, ctx=ctx, reason="bad_current_password",
            message="The current password is incorrect.",
        )
    policy = await asyncio.to_thread(
        validate_password_policy, new_password, username=user.username, email=user.email,
        history_hashes=list(user.password_history),
    )
    if not policy.valid:
        raise bad_request("weak_password", " ".join(policy.errors), 422)
    new_hash = await asyncio.to_thread(hash_password, new_password)

    await begin_write(db)
    await db.refresh(user)
    user.password_hash = new_hash
    user.password_history = ([new_hash] + list(user.password_history))[:PASSWORD_HISTORY]
    user.must_change_password = False
    user.password_changed_at = utcnow()
    others = (
        await db.execute(
            select(AuthSession).where(
                AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None),
                AuthSession.id != uuid.UUID(claims.session_id),
            )
        )
    ).scalars().all()
    for s in others:
        await _revoke_session(db, s, "password_changed")
    await audit_service.record(
        db, action=AuditAction.PASSWORD_CHANGE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="user", resource_id=user.id, details={"sessions_revoked": len(others)},
    )
    await db.commit()


# --------------------------------------------------------------------------
# MFA (TOTP)
# --------------------------------------------------------------------------
async def enroll_mfa(db: AsyncSession, *, user: User, ctx: RequestContext) -> tuple[str, str]:
    if user.mfa_enabled:
        raise conflict("mfa_already_enabled", "MFA is already enabled for this account.")
    secret = generate_totp_secret()
    await begin_write(db)
    await db.refresh(user)
    user.mfa_secret_enc = encrypt_totp_secret(secret)
    user.mfa_last_counter = 0
    await audit_service.record(
        db, action=AuditAction.MFA_ENROLL, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="user", resource_id=user.id, details={"stage": "secret_issued"},
    )
    await db.commit()
    return secret, totp_provisioning_uri(secret, user.email)


async def verify_mfa(
    db: AsyncSession, *, user: User, claims: TokenClaims, code: str, ctx: RequestContext
) -> tuple[str, list[str], bool]:
    """Confirm enrolment (first call) or step up the current session. Returns (access_token, backup_codes, first)."""
    if not user.mfa_secret_enc:
        raise conflict("mfa_not_enrolled", "Start MFA enrolment first.")
    secret = decrypt_totp_secret(user.mfa_secret_enc)
    await begin_write(db)
    await db.refresh(user)
    counter = verify_totp(secret, code, last_used_counter=user.mfa_last_counter)
    if counter is None:
        raise await _register_failure(
            db, user, username=user.username, ctx=ctx, reason="bad_mfa_code", action=AuditAction.MFA_FAILURE,
            message="Invalid verification code.",
        )
    user.mfa_last_counter = counter
    first = not user.mfa_enabled
    backup_display: list[str] = []
    if first:
        backup_display, hashes = await asyncio.to_thread(generate_backup_codes)
        user.mfa_enabled = True
        user.backup_codes_hash = hashes
    session = await db.get(AuthSession, uuid.UUID(claims.session_id))
    if session is not None:
        session.mfa_verified = True
    access = create_access_token(
        user_id=user.id, role=user.role.value, session_id=claims.session_id, mfa_verified=True
    )
    await audit_service.record(
        db, action=AuditAction.MFA_ENROLL, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="user", resource_id=user.id, details={"stage": "enabled" if first else "step_up"},
    )
    await db.commit()
    return access.token, backup_display, first
