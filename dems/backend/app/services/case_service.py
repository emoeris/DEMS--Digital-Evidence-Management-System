"""Case management: create, read, update, close, delete, and investigator assignment."""
from __future__ import annotations

import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import compute_chain_hash
from app.db.models import (
    AuditAction, Case, CaseAssignment, CaseStatus, CustodyAction, CustodyEvent, Evidence, Outcome, Role, User, utcnow,
)
from app.db.session import begin_write
from app.services import audit_service
from app.services.access import authorize_case, is_assigned
from app.services.context import RequestContext
from app.services.errors import bad_request, conflict, forbidden, not_found
from app.services.evidence_service import chain_append

MANIFEST_DOMAIN = b"DEMS-CASE-MANIFEST-V1"


async def _active_user(db: AsyncSession, user_id: uuid.UUID, *, roles: set[Role]) -> User:
    user = await db.get(User, user_id)
    if user is None or not user.is_active or user.role not in roles:
        raise bad_request("invalid_user", "The selected user does not exist, is inactive, or has the wrong role.", 422)
    return user


def _can_manage(case: Case, user: User) -> bool:
    return user.role == Role.ADMIN or (user.role == Role.INVESTIGATOR and case.lead_investigator_id == user.id)


async def _lock_open_case(db: AsyncSession, case_id: uuid.UUID, user: User, *, need_manage: bool = True) -> Case:
    """Authorise, take the write lock, and re-read the case row so decisions use current state."""
    case = await authorize_case(db, case_id, user, "metadata")
    if user.role == Role.INVESTIGATOR and not await is_assigned(db, case_id, user.id):
        raise not_found("Case")
    if need_manage and not _can_manage(case, user):
        raise forbidden("Only an administrator or the lead investigator can do that.")
    await begin_write(db)
    return (
        await db.execute(select(Case).where(Case.id == case_id).with_for_update().execution_options(populate_existing=True))
    ).scalar_one()


async def create_case(
    db: AsyncSession, *, actor: User, case_number: str, title: str, description: str | None,
    lead_investigator_id: uuid.UUID | None, ctx: RequestContext,
) -> Case:
    if actor.role == Role.INVESTIGATOR:
        lead_id = actor.id  # investigators lead the cases they create
        if lead_investigator_id not in (None, actor.id):
            raise forbidden("Investigators can only create cases that they lead themselves.")
    else:
        lead_id = lead_investigator_id
    if lead_id is not None:
        await _active_user(db, lead_id, roles={Role.INVESTIGATOR})

    await begin_write(db)
    if (await db.execute(select(Case.id).where(Case.case_number == case_number))).first():
        raise conflict("case_exists", "A case with that number already exists.")
    case = Case(case_number=case_number, title=title, description=description, status=CaseStatus.OPEN,
                lead_investigator_id=lead_id, created_by=actor.id)
    db.add(case)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise conflict("case_exists", "A case with that number already exists.") from None
    if lead_id is not None:
        db.add(CaseAssignment(case_id=case.id, user_id=lead_id, assigned_by=actor.id))
    await audit_service.record(
        db, action=AuditAction.CASE_CREATE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=actor.id,
        resource_type="case", resource_id=case.id, details={"case_number": case_number, "lead": str(lead_id) if lead_id else None},
    )
    await db.commit()
    return case


async def list_cases(
    db: AsyncSession, *, user: User, status: CaseStatus | None, limit: int, offset: int
) -> tuple[list[Case], int]:
    conditions = []
    if status:
        conditions.append(Case.status == status)
    if user.role == Role.INVESTIGATOR:
        assigned = select(CaseAssignment.case_id).where(
            CaseAssignment.user_id == user.id, CaseAssignment.revoked_at.is_(None)
        )
        conditions.append(Case.id.in_(assigned))
    total = (await db.execute(select(func.count()).select_from(Case).where(*conditions))).scalar_one()
    rows = (
        await db.execute(select(Case).where(*conditions).order_by(Case.created_at.desc(), Case.id).limit(limit).offset(offset))
    ).scalars().all()
    return list(rows), total


async def get_case(db: AsyncSession, *, case_id: uuid.UUID, user: User) -> Case:
    return await authorize_case(db, case_id, user, "metadata")


async def update_case(
    db: AsyncSession, *, case_id: uuid.UUID, user: User, title: str | None, description: str | None,
    lead_investigator_id: uuid.UUID | None, ctx: RequestContext,
) -> Case:
    case = await _lock_open_case(db, case_id, user)
    if case.status != CaseStatus.OPEN:
        raise conflict("case_closed", "A closed case cannot be modified.")
    changes: dict[str, str | None] = {}
    if title is not None and title != case.title:
        changes["title"] = title
        case.title = title
    if description is not None and description != case.description:
        changes["description"] = "updated"
        case.description = description
    if lead_investigator_id is not None and lead_investigator_id != case.lead_investigator_id:
        if user.role != Role.ADMIN:
            raise forbidden("Only an administrator can change the lead investigator.")
        await _active_user(db, lead_investigator_id, roles={Role.INVESTIGATOR})
        if not await is_assigned(db, case.id, lead_investigator_id):
            db.add(CaseAssignment(case_id=case.id, user_id=lead_investigator_id, assigned_by=user.id))
        case.lead_investigator_id = lead_investigator_id
        changes["lead_investigator_id"] = str(lead_investigator_id)
    await audit_service.record(
        db, action=AuditAction.CASE_UPDATE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="case", resource_id=case.id, details={"changed": changes},
    )
    await db.commit()
    return case


async def close_case(db: AsyncSession, *, case_id: uuid.UUID, user: User, ctx: RequestContext) -> Case:
    """Lock the case. The closure manifest hash covers every live evidence item, and is chained."""
    case = await _lock_open_case(db, case_id, user)
    if case.status != CaseStatus.OPEN:
        raise conflict("case_closed", "The case is already closed.")
    items = (
        await db.execute(
            select(Evidence.id, Evidence.sha256_server)
            .where(Evidence.case_id == case.id, Evidence.deleted_at.is_(None))
            .order_by(Evidence.uploaded_at, Evidence.id)
        )
    ).all()
    manifest = compute_chain_hash(MANIFEST_DOMAIN, [f"{i}:{h}" for i, h in items])
    case.status = CaseStatus.CLOSED
    case.closed_at = utcnow()
    case.closed_by = user.id
    case.closure_manifest_hash = manifest
    await chain_append(
        db, case_id=case.id, actor=user, action=CustodyAction.CASE_CLOSE, outcome=Outcome.SUCCESS, ctx=ctx,
        details={"closure_manifest_hash": manifest, "evidence_count": len(items)},
    )
    await audit_service.record(
        db, action=AuditAction.CASE_CLOSE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="case", resource_id=case.id, details={"closure_manifest_hash": manifest},
    )
    await db.commit()
    return case


async def delete_case(db: AsyncSession, *, case_id: uuid.UUID, admin: User, ctx: RequestContext) -> None:
    """Only a case with no evidence and no custody history can be removed (nothing forensic is lost)."""
    case = await _lock_open_case(db, case_id, admin)
    has_evidence = (await db.execute(select(Evidence.id).where(Evidence.case_id == case.id).limit(1))).first()
    has_custody = (await db.execute(select(CustodyEvent.id).where(CustodyEvent.chain_id == case.id).limit(1))).first()
    if has_evidence or has_custody:
        raise conflict("case_has_records", "Cases with evidence or custody history cannot be deleted; close the case instead.")
    case_number = case.case_number
    await db.execute(delete(CaseAssignment).where(CaseAssignment.case_id == case.id))
    await db.execute(delete(Case).where(Case.id == case.id))  # Core delete: relationships are lazy="raise"
    await audit_service.record(
        db, action=AuditAction.CASE_DELETE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=admin.id,
        resource_type="case", resource_id=case_id, details={"case_number": case_number},
    )
    await db.commit()


async def assign_investigator(
    db: AsyncSession, *, case_id: uuid.UUID, user: User, investigator_id: uuid.UUID, ctx: RequestContext
) -> CaseAssignment:
    case = await _lock_open_case(db, case_id, user)
    if case.status != CaseStatus.OPEN:
        raise conflict("case_closed", "Assignments cannot change on a closed case.")
    await _active_user(db, investigator_id, roles={Role.INVESTIGATOR})
    if await is_assigned(db, case.id, investigator_id):
        raise conflict("already_assigned", "That investigator is already assigned.")
    assignment = CaseAssignment(case_id=case.id, user_id=investigator_id, assigned_by=user.id)
    db.add(assignment)
    await db.flush()
    await audit_service.record(
        db, action=AuditAction.CASE_ASSIGN, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="case", resource_id=case.id, details={"investigator_id": str(investigator_id)},
    )
    await db.commit()
    return assignment


async def unassign_investigator(
    db: AsyncSession, *, case_id: uuid.UUID, user: User, investigator_id: uuid.UUID, ctx: RequestContext
) -> None:
    case = await _lock_open_case(db, case_id, user)
    if case.status != CaseStatus.OPEN:
        raise conflict("case_closed", "Assignments cannot change on a closed case.")
    if investigator_id == case.lead_investigator_id:
        raise conflict("lead_assigned", "Reassign the lead investigator before removing them from the case.")
    row = (
        await db.execute(
            select(CaseAssignment).where(
                CaseAssignment.case_id == case.id, CaseAssignment.user_id == investigator_id,
                CaseAssignment.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise not_found("Assignment")
    row.revoked_at = utcnow()
    row.revoked_by = user.id
    await audit_service.record(
        db, action=AuditAction.CASE_UNASSIGN, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="case", resource_id=case.id, details={"investigator_id": str(investigator_id)},
    )
    await db.commit()


async def list_assignments(db: AsyncSession, *, case_id: uuid.UUID, user: User) -> list[CaseAssignment]:
    await authorize_case(db, case_id, user, "metadata")
    rows = await db.execute(
        select(CaseAssignment).where(CaseAssignment.case_id == case_id, CaseAssignment.revoked_at.is_(None))
        .order_by(CaseAssignment.assigned_at)
    )
    return list(rows.scalars().all())


async def list_evidence(
    db: AsyncSession, *, case_id: uuid.UUID, user: User, ctx: RequestContext, limit: int, offset: int
) -> tuple[list[Evidence], int]:
    await authorize_case(db, case_id, user, "metadata")
    cond = [Evidence.case_id == case_id, Evidence.deleted_at.is_(None)]
    total = (await db.execute(select(func.count()).select_from(Evidence).where(*cond))).scalar_one()
    rows = (
        await db.execute(select(Evidence).where(*cond).order_by(Evidence.uploaded_at, Evidence.id).limit(limit).offset(offset))
    ).scalars().all()
    await audit_service.record(
        db, action=AuditAction.EVIDENCE_READ, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
        resource_type="case", resource_id=case_id, details={"listing": True, "returned": len(rows)},
    )
    await db.commit()
    return list(rows), total
