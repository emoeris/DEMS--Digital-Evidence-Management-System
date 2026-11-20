"""Object-level authorisation (case membership), enforced server-side on every request."""
from __future__ import annotations

import uuid
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Case, CaseAssignment, Role, User
from app.services.errors import forbidden, not_found

AccessLevel = Literal["metadata", "content", "write"]
"""metadata: view case/evidence metadata and custody. content: download evidence. write: upload evidence."""


async def is_assigned(db: AsyncSession, case_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    row = await db.execute(
        select(CaseAssignment.id).where(
            CaseAssignment.case_id == case_id, CaseAssignment.user_id == user_id, CaseAssignment.revoked_at.is_(None)
        )
    )
    return row.first() is not None


async def load_case(db: AsyncSession, case_id: uuid.UUID) -> Case:
    case = await db.get(Case, case_id)
    if case is None:
        raise not_found("Case")
    return case


async def authorize_case(db: AsyncSession, case_id: uuid.UUID, user: User, level: AccessLevel) -> Case:
    """Return the case if ``user`` may act on it at ``level``.

    * Admin: metadata for all cases; content only when assigned; never uploads.
    * Auditor: metadata for all cases (read-only); never content or uploads.
    * Investigator: everything, but only for cases they are assigned to.
    Unassigned objects look like 404 so IDs cannot be probed.
    """
    case = await load_case(db, case_id)
    role = user.role
    if role == Role.AUDITOR:
        if level == "metadata":
            return case
        raise forbidden("Auditors have read-only access to metadata.")
    if role == Role.ADMIN:
        if level == "write":
            raise forbidden("Administrators cannot upload evidence.")
        if level == "metadata" or await is_assigned(db, case_id, user.id):
            return case
        raise not_found("Case")
    if role == Role.INVESTIGATOR:
        if await is_assigned(db, case_id, user.id):
            return case
        raise not_found("Case")
    raise forbidden()
