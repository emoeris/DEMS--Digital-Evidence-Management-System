from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import CtxDep, DbDep, require_role
from app.db.models import AuditAction, CustodyEvent, Outcome, Role, User
from app.schemas.common import Page
from app.schemas.custody import ChainVerifyOut, CustodyEventOut
from app.services import audit_service, evidence_service
from app.services.access import authorize_case

router = APIRouter(prefix="/custody", tags=["custody"])
AnyRole = Annotated[User, Depends(require_role(Role.ADMIN, Role.INVESTIGATOR, Role.AUDITOR))]


def _serialize_custody_event(row: CustodyEvent, usernames: dict[uuid.UUID, str]) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": row.id,
        "chain_id": row.chain_id,
        "sequence_no": row.sequence_no,
        "evidence_id": row.evidence_id,
        "actor_id": row.actor_id,
        "actor_username": usernames.get(row.actor_id),
        "actor_role": row.actor_role,
        "action": row.action,
        "outcome": row.outcome,
        "occurred_at": row.occurred_at,
        "source_ip": row.source_ip,
        "details_json": row.details_json,
        "prev_event_hash": row.prev_event_hash,
        "event_hash": row.event_hash,
    }
    return payload


@router.get("/{case_id}", response_model=Page[CustodyEventOut])
async def get_custody_chain(
    case_id: uuid.UUID, user: AnyRole, db: DbDep, ctx: CtxDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100, offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[CustodyEventOut]:
    await authorize_case(db, case_id, user, "metadata")
    total = (await db.execute(select(func.count()).select_from(CustodyEvent).where(CustodyEvent.chain_id == case_id))).scalar_one()
    rows = (
        await db.execute(
            select(CustodyEvent).where(CustodyEvent.chain_id == case_id)
            .order_by(CustodyEvent.sequence_no).limit(limit).offset(offset)
        )
    ).scalars().all()
    usernames = await audit_service.resolve_usernames(db, [r.actor_id for r in rows if r.actor_id is not None])
    items = [CustodyEventOut.model_validate(_serialize_custody_event(r, usernames)) for r in rows]
    await audit_service.record(db, action=AuditAction.CUSTODY_READ, outcome=Outcome.SUCCESS, ctx=ctx,
                               actor_id=user.id, resource_type="case", resource_id=case_id)
    await db.commit()
    return Page[CustodyEventOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/{case_id}/verify", response_model=ChainVerifyOut)
async def verify_custody_chain(case_id: uuid.UUID, user: AnyRole, db: DbDep, ctx: CtxDep) -> ChainVerifyOut:
    await authorize_case(db, case_id, user, "metadata")
    result = await evidence_service.verify_chain(db, case_id)
    await audit_service.record(
        db, action=AuditAction.CHAIN_VERIFY, outcome=Outcome.SUCCESS if result.valid else Outcome.FAILURE, ctx=ctx,
        actor_id=user.id, resource_type="case", resource_id=case_id,
        details={"valid": result.valid, "failure_type": result.failure_type, "checked": result.events_checked},
    )
    await db.commit()
    return ChainVerifyOut(**result.__dict__)
