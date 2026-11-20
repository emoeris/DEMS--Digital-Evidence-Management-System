"""Generic verifier for the hash-chained, HMAC-protected ledgers (custody events and audit log).

Detects (first failure wins, scanning in sequence order):
  GAP               a sequence number is missing (row deleted) or out of order
  BAD_GENESIS       first entry does not start from the chain's genesis hash
  LINK_BROKEN       prev hash differs from the previous entry's hash (row altered, inserted or removed)
  CONTENT_TAMPERED  stored hash differs from the hash recomputed over the stored fields
  HMAC_INVALID      hash was recomputed but the HMAC (needs the secret audit key) does not verify

Truncation of the *tail* of a chain cannot be detected from the chain alone; compare ``head_hash``
with an externally recorded checkpoint (for example in a signed backup manifest).
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import constant_time_equals, get_key_service

BATCH_SIZE = 1000


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    events_checked: int
    head_hash: str | None
    broken_at_event_id: uuid.UUID | None = None
    broken_at_sequence: int | None = None
    failure_type: str | None = None


async def verify_chain_generic(
    db: AsyncSession,
    model: Any,
    *,
    where: Sequence[Any],
    prev_attr: str,
    hash_attr: str,
    hmac_attr: str,
    recompute: Callable[[Any], str],
    genesis: str,
    batch_size: int = BATCH_SIZE,
) -> ChainVerification:
    keys = get_key_service()
    expected_seq = 1
    prev_hash = genesis
    checked = 0
    last_seq = 0

    def broken(row: Any, kind: str) -> ChainVerification:
        return ChainVerification(False, checked, prev_hash if checked else None, row.id, row.sequence_no, kind)

    while True:
        rows = (
            await db.execute(
                select(model).where(*where, model.sequence_no > last_seq).order_by(model.sequence_no).limit(batch_size)
            )
        ).scalars().all()
        if not rows:
            break
        for row in rows:
            if row.sequence_no != expected_seq:
                return broken(row, "GAP")
            if not constant_time_equals(getattr(row, prev_attr), prev_hash):
                return broken(row, "BAD_GENESIS" if expected_seq == 1 else "LINK_BROKEN")
            stored_hash = getattr(row, hash_attr)
            if not constant_time_equals(recompute(row), stored_hash):
                return broken(row, "CONTENT_TAMPERED")
            if row.hmac_key_version != keys.hmac_key_version or not keys.verify_audit_hmac(
                stored_hash, getattr(row, hmac_attr)
            ):
                return broken(row, "HMAC_INVALID")
            prev_hash = stored_hash
            expected_seq += 1
            checked += 1
            last_seq = row.sequence_no
        if len(rows) < batch_size:
            break
    return ChainVerification(True, checked, prev_hash if checked else None)
