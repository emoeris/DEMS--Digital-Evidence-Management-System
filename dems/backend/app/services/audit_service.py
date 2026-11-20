"""Append-only, hash-chained, HMAC-protected audit log."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import (
    AUDIT_CHAIN_ID, compute_audit_entry_hash, details_hash, genesis_hash, get_key_service,
)
from app.db.models import AuditAction, AuditLog, Outcome, User, utcnow
from app.db.session import begin_write
from app.services.chain import ChainVerification, verify_chain_generic
from app.services.context import RequestContext

_AUDIT_ADVISORY_LOCK = 7_283_461_001
_SENSITIVE = re.compile(r"pass(word|phrase)|secret|token|dek|private|authorization|cookie", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _scrub(value: Any) -> Any:
    """Drop anything that looks like a credential, so details can never leak secrets."""
    if isinstance(value, dict):
        return {str(k): ("[redacted]" if _SENSITIVE.search(str(k)) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    return value


def _normalise_details(details: dict[str, Any] | None) -> dict[str, Any]:
    # Round-trip through canonical JSON so the hashed form equals what the database returns.
    return json.loads(json.dumps(_scrub(details or {}), default=str, sort_keys=True))


async def record(
    db: AsyncSession,
    *,
    action: AuditAction | str,
    outcome: Outcome,
    ctx: RequestContext,
    actor_id: uuid.UUID | None = None,
    username_attempted: str | None = None,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one audit entry. Takes the write lock, so concurrent appends cannot fork the chain.

    The caller commits, so an action and its audit entry are one atomic transaction.
    """
    await begin_write(db)
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(select(func.pg_advisory_xact_lock(_AUDIT_ADVISORY_LOCK)))

    last = (
        await db.execute(select(AuditLog).order_by(AuditLog.sequence_no.desc()).limit(1))
    ).scalar_one_or_none()
    sequence_no = 1 if last is None else last.sequence_no + 1
    prev_hash = genesis_hash(AUDIT_CHAIN_ID) if last is None else last.entry_hash

    occurred_at = utcnow()
    clean_details = _normalise_details(details)
    dhash = details_hash(clean_details)
    attempted = _CONTROL.sub("", username_attempted)[:64] if username_attempted else None
    action_s = str(action)

    entry_hash = compute_audit_entry_hash(
        sequence_no=sequence_no, prev_hash=prev_hash, occurred_at=occurred_at, actor_id=actor_id,
        actor_username_attempted=attempted, action=action_s, resource_type=resource_type,
        resource_id=resource_id, outcome=outcome.value, source_ip=ctx.ip,
        user_agent_hash=ctx.user_agent_hash, details_hash_hex=dhash,
    )
    keys = get_key_service()
    row = AuditLog(
        sequence_no=sequence_no, occurred_at=occurred_at, actor_id=actor_id, actor_username_attempted=attempted,
        action=action_s, resource_type=resource_type, resource_id=resource_id, outcome=outcome,
        source_ip=ctx.ip, user_agent_hash=ctx.user_agent_hash, details_json=clean_details, details_hash=dhash,
        prev_hash=prev_hash, entry_hash=entry_hash, entry_hmac=keys.audit_hmac(entry_hash),
        hmac_key_version=keys.hmac_key_version,
    )
    db.add(row)
    await db.flush()
    return row


def _recompute(row: AuditLog) -> str:
    return compute_audit_entry_hash(
        sequence_no=row.sequence_no, prev_hash=row.prev_hash, occurred_at=row.occurred_at, actor_id=row.actor_id,
        actor_username_attempted=row.actor_username_attempted, action=row.action, resource_type=row.resource_type,
        resource_id=row.resource_id, outcome=row.outcome.value, source_ip=row.source_ip,
        user_agent_hash=row.user_agent_hash, details_hash_hex=details_hash(row.details_json),
    )


async def verify_audit_chain(db: AsyncSession) -> ChainVerification:
    return await verify_chain_generic(
        db, AuditLog, where=[], prev_attr="prev_hash", hash_attr="entry_hash", hmac_attr="entry_hmac",
        recompute=_recompute, genesis=genesis_hash(AUDIT_CHAIN_ID),
    )


async def resolve_usernames(db: AsyncSession, actor_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    unique_ids = list({uid for uid in actor_ids if uid is not None})
    if not unique_ids:
        return {}
    rows = (await db.execute(select(User.id, User.username).where(User.id.in_(unique_ids)))).all()
    return {uid: username for uid, username in rows}


async def query(
    db: AsyncSession,
    *,
    action: str | None = None,
    actor_id: uuid.UUID | None = None,
    outcome: Outcome | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuditLog], int]:
    conditions = []
    if action:
        conditions.append(AuditLog.action == action)
    if actor_id:
        conditions.append(AuditLog.actor_id == actor_id)
    if outcome:
        conditions.append(AuditLog.outcome == outcome)
    if since:
        conditions.append(AuditLog.occurred_at >= since)
    if until:
        conditions.append(AuditLog.occurred_at <= until)
    total = (await db.execute(select(func.count()).select_from(AuditLog).where(*conditions))).scalar_one()
    rows = (
        await db.execute(
            select(AuditLog).where(*conditions).order_by(AuditLog.sequence_no.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return list(rows), total
