"""FastAPI dependencies: DB session, authentication, request context, and RBAC guards."""
from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import TokenClaims, TokenError, TokenExpiredError, decode_token
from app.db.models import AuditAction, AuthSession, Outcome, RevokedAccessToken, Role, User, utcnow
from app.db.session import get_db  # re-exported: the per-request async session dependency
from app.services import audit_service
from app.services.context import RequestContext
from app.services.errors import ServiceError, forbidden, unauthorized

__all__ = [
    "CtxDep", "DbDep", "Principal", "get_current_principal", "get_current_principal_any", "get_current_user",
    "get_db", "get_request_context", "require_role",
]

_bearer = HTTPBearer(auto_error=False, description="Access token from POST /auth/login")


@dataclass(frozen=True)
class Principal:
    user: User
    claims: TokenClaims


def get_request_context(request: Request) -> RequestContext:
    client_ip = request.client.host if request.client else None
    return RequestContext.build(client_ip, request.headers.get("user-agent"))


DbDep = Annotated[AsyncSession, Depends(get_db)]
CtxDep = Annotated[RequestContext, Depends(get_request_context)]


async def _authenticate(
    credentials: HTTPAuthorizationCredentials | None, db: AsyncSession
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized("not_authenticated", "Authentication required.")
    try:
        claims = decode_token(credentials.credentials, expected_type="access")
    except TokenExpiredError:
        raise unauthorized("token_expired", "The access token has expired.") from None
    except TokenError:
        raise unauthorized("invalid_token", "Invalid access token.") from None

    if await db.get(RevokedAccessToken, claims.jti) is not None:
        raise unauthorized("invalid_token", "The access token has been revoked.")
    try:
        session = await db.get(AuthSession, uuid.UUID(claims.session_id))
        user = await db.get(User, uuid.UUID(claims.subject))
    except ValueError:
        raise unauthorized("invalid_token", "Invalid access token.") from None
    if session is None or session.revoked_at is not None or session.expires_at <= utcnow():
        raise unauthorized("session_ended", "The session is no longer valid.")
    if user is None or not user.is_active or session.user_id != user.id:
        raise unauthorized("invalid_token", "Invalid access token.")
    return Principal(user=user, claims=claims)


async def get_current_principal_any(
    db: DbDep, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]
) -> Principal:
    """Authenticated principal without onboarding checks (change-password, logout, MFA enrolment)."""
    return await _authenticate(credentials, db)


async def get_current_principal(
    principal: Annotated[Principal, Depends(get_current_principal_any)],
) -> Principal:
    user, claims = principal.user, principal.claims
    if user.must_change_password:
        raise ServiceError(403, "password_change_required", "You must change your password before continuing.")
    if user.role == Role.ADMIN and get_settings().require_admin_mfa and not claims.mfa_verified:
        raise ServiceError(403, "mfa_required", "Administrators must complete MFA to continue.")
    return principal


async def get_current_user(principal: Annotated[Principal, Depends(get_current_principal)]) -> User:
    return principal.user


def require_role(*roles: Role) -> Callable[..., Awaitable[User]]:
    """RBAC guard: ``user: Annotated[User, Depends(require_role(Role.ADMIN))]``.

    Denials are written to the audit log before the 403 is returned.
    """
    allowed = frozenset(roles)

    async def checker(
        request: Request,
        user: Annotated[User, Depends(get_current_user)],
        db: DbDep,
        ctx: CtxDep,
    ) -> User:
        if user.role not in allowed:
            await audit_service.record(
                db, action=AuditAction.AUTHZ_DENIED, outcome=Outcome.DENIED, ctx=ctx, actor_id=user.id,
                details={"method": request.method, "path": request.url.path, "role": user.role.value,
                         "required": sorted(r.value for r in allowed)},
            )
            await db.commit()
            raise forbidden()
        return user

    return checker
