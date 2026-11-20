from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CtxDep, DbDep, require_role
from app.db.models import AuditAction, Outcome, Role, User
from app.schemas.audit import AuditEntryOut
from app.schemas.common import Page
from app.schemas.custody import ChainVerifyOut
from app.services import audit_service

router = APIRouter(prefix="/audit", tags=["audit"])
Reader = Annotated[User, Depends(require_role(Role.ADMIN, Role.AUDITOR))]


@router.get("", response_model=Page[AuditEntryOut])
async def list_audit(
    user: Reader, db: DbDep, ctx: CtxDep,
    action: Annotated[str | None, Query(max_length=48)] = None,
    actor_id: uuid.UUID | None = None,
    outcome: Outcome | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditEntryOut]:
    rows, total = await audit_service.query(
        db, action=action, actor_id=actor_id, outcome=outcome, since=since, until=until, limit=limit, offset=offset
    )
    usernames = await audit_service.resolve_usernames(db, [r.actor_id for r in rows if r.actor_id is not None])
    items: list[AuditEntryOut] = []
    for r in rows:
        out = AuditEntryOut.model_validate(r)
        out.actor_username = usernames.get(r.actor_id) if r.actor_id else r.actor_username_attempted
        items.append(out)
    await audit_service.record(db, action=AuditAction.AUDIT_READ, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
                               details={"filters": {"action": action, "outcome": outcome.value if outcome else None}})
    await db.commit()
    return Page[AuditEntryOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/verify", response_model=ChainVerifyOut)
async def verify_audit(user: Reader, db: DbDep, ctx: CtxDep) -> ChainVerifyOut:
    """Recompute the audit chain and every entry's HMAC."""
    result = await audit_service.verify_audit_chain(db)
    await audit_service.record(
        db, action=AuditAction.AUDIT_VERIFY, outcome=Outcome.SUCCESS if result.valid else Outcome.FAILURE, ctx=ctx,
        actor_id=user.id, details={"valid": result.valid, "failure_type": result.failure_type},
    )
    await db.commit()
    return ChainVerifyOut(**result.__dict__)
