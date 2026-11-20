from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import CtxDep, DbDep, require_role
from app.db.models import Case, CaseAssignment, CaseStatus, Role, User
from app.schemas.cases import AssignmentCreate, AssignmentOut, CaseCreate, CaseOut, CaseUpdate
from app.schemas.common import Page
from app.schemas.evidence import EvidenceOut
from app.services import audit_service, case_service

router = APIRouter(prefix="/cases", tags=["cases"])
AnyRole = Annotated[User, Depends(require_role(Role.ADMIN, Role.INVESTIGATOR, Role.AUDITOR))]
Manager = Annotated[User, Depends(require_role(Role.ADMIN, Role.INVESTIGATOR))]
AdminOnly = Annotated[User, Depends(require_role(Role.ADMIN))]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


def _to_case_out(case: Case, usernames: dict[uuid.UUID, str]) -> CaseOut:
    out = CaseOut.model_validate(case)
    if case.lead_investigator_id is not None:
        out.lead_investigator_username = usernames.get(case.lead_investigator_id)
    return out


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(body: CaseCreate, user: Manager, db: DbDep, ctx: CtxDep) -> CaseOut:
    created = await case_service.create_case(
        db, actor=user, case_number=body.case_number, title=body.title, description=body.description,
        lead_investigator_id=body.lead_investigator_id, ctx=ctx,
    )
    usernames = await audit_service.resolve_usernames(
        db, [created.lead_investigator_id] if created.lead_investigator_id is not None else []
    )
    return _to_case_out(created, usernames)


@router.get("", response_model=Page[CaseOut])
async def list_cases(
    user: AnyRole, db: DbDep, status_filter: Annotated[CaseStatus | None, Query(alias="status")] = None,
    limit: Limit = 50, offset: Offset = 0,
) -> Page[CaseOut]:
    rows, total = await case_service.list_cases(db, user=user, status=status_filter, limit=limit, offset=offset)
    usernames = await audit_service.resolve_usernames(
        db, [r.lead_investigator_id for r in rows if r.lead_investigator_id is not None]
    )
    return Page[CaseOut](
        items=[_to_case_out(r, usernames) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(case_id: uuid.UUID, user: AnyRole, db: DbDep) -> CaseOut:
    row = await case_service.get_case(db, case_id=case_id, user=user)
    usernames = await audit_service.resolve_usernames(
        db, [row.lead_investigator_id] if row.lead_investigator_id is not None else []
    )
    return _to_case_out(row, usernames)


@router.patch("/{case_id}", response_model=CaseOut)
async def update_case(case_id: uuid.UUID, body: CaseUpdate, user: Manager, db: DbDep, ctx: CtxDep) -> CaseOut:
    row = await case_service.update_case(
        db, case_id=case_id, user=user, title=body.title, description=body.description,
        lead_investigator_id=body.lead_investigator_id, ctx=ctx,
    )
    usernames = await audit_service.resolve_usernames(
        db, [row.lead_investigator_id] if row.lead_investigator_id is not None else []
    )
    return _to_case_out(row, usernames)


@router.post("/{case_id}/close", response_model=CaseOut)
async def close_case(case_id: uuid.UUID, user: Manager, db: DbDep, ctx: CtxDep) -> CaseOut:
    row = await case_service.close_case(db, case_id=case_id, user=user, ctx=ctx)
    usernames = await audit_service.resolve_usernames(
        db, [row.lead_investigator_id] if row.lead_investigator_id is not None else []
    )
    return _to_case_out(row, usernames)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(case_id: uuid.UUID, admin: AdminOnly, db: DbDep, ctx: CtxDep) -> Response:
    await case_service.delete_case(db, case_id=case_id, admin=admin, ctx=ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{case_id}/assignments", response_model=list[AssignmentOut])
async def list_assignments(case_id: uuid.UUID, user: AnyRole, db: DbDep) -> list[CaseAssignment]:
    return await case_service.list_assignments(db, case_id=case_id, user=user)


@router.post("/{case_id}/assignments", response_model=AssignmentOut, status_code=status.HTTP_201_CREATED)
async def assign(case_id: uuid.UUID, body: AssignmentCreate, user: Manager, db: DbDep, ctx: CtxDep) -> CaseAssignment:
    return await case_service.assign_investigator(db, case_id=case_id, user=user, investigator_id=body.user_id, ctx=ctx)


@router.delete("/{case_id}/assignments/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unassign(case_id: uuid.UUID, user_id: uuid.UUID, user: Manager, db: DbDep, ctx: CtxDep) -> Response:
    await case_service.unassign_investigator(db, case_id=case_id, user=user, investigator_id=user_id, ctx=ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{case_id}/evidence", response_model=Page[EvidenceOut])
async def list_case_evidence(
    case_id: uuid.UUID, user: AnyRole, db: DbDep, ctx: CtxDep, limit: Limit = 50, offset: Offset = 0
) -> Page[EvidenceOut]:
    rows, total = await case_service.list_evidence(db, case_id=case_id, user=user, ctx=ctx, limit=limit, offset=offset)
    return Page[EvidenceOut](items=[EvidenceOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)
