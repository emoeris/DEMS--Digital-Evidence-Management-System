from __future__ import annotations

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.api.deps import CtxDep, DbDep, Principal, get_current_principal_any, require_role
from app.db.models import Role, User
from app.schemas.auth import (
    ChangePasswordRequest, LoginRequest, MeResponse, MFAEnrollResponse, MFAVerifyRequest, MFAVerifyResponse,
    RefreshRequest, TokenPair,
)
from app.schemas.users import UserCreate, UserOut
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])
AnyPrincipal = Annotated[Principal, Depends(get_current_principal_any)]


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserCreate, admin: Annotated[User, Depends(require_role(Role.ADMIN))], db: DbDep, ctx: CtxDep
) -> User:
    """Admin-only account creation. There is no self-registration."""
    return await auth_service.register_user(
        db, admin=admin, username=body.username, email=body.email, password=body.password, role=body.role, ctx=ctx
    )


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, db: DbDep, ctx: CtxDep) -> TokenPair:
    bundle = await auth_service.login(
        db, username=body.username, password=body.password, totp_code=body.totp_code,
        backup_code=body.backup_code, ctx=ctx,
    )
    return TokenPair(**asdict(bundle))


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, db: DbDep, ctx: CtxDep) -> TokenPair:
    bundle = await auth_service.refresh(db, refresh_token=body.refresh_token, ctx=ctx)
    return TokenPair(**asdict(bundle))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(principal: AnyPrincipal, db: DbDep, ctx: CtxDep) -> Response:
    await auth_service.logout(db, user=principal.user, claims=principal.claims, ctx=ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse)
async def me(principal: AnyPrincipal) -> MeResponse:
    return MeResponse(user=UserOut.model_validate(principal.user), session_mfa_verified=principal.claims.mfa_verified)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(body: ChangePasswordRequest, principal: AnyPrincipal, db: DbDep, ctx: CtxDep) -> Response:
    await auth_service.change_password(
        db, user=principal.user, claims=principal.claims, current_password=body.current_password,
        new_password=body.new_password, ctx=ctx,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mfa/enroll", response_model=MFAEnrollResponse)
async def mfa_enroll(principal: AnyPrincipal, db: DbDep, ctx: CtxDep) -> MFAEnrollResponse:
    secret, uri = await auth_service.enroll_mfa(db, user=principal.user, ctx=ctx)
    return MFAEnrollResponse(secret=secret, provisioning_uri=uri)


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def mfa_verify(body: MFAVerifyRequest, principal: AnyPrincipal, db: DbDep, ctx: CtxDep) -> MFAVerifyResponse:
    access, backup_codes, _first = await auth_service.verify_mfa(
        db, user=principal.user, claims=principal.claims, code=body.code, ctx=ctx
    )
    return MFAVerifyResponse(mfa_enabled=True, access_token=access, backup_codes=backup_codes)
