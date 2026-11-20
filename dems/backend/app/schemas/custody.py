from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.db.models import Outcome
from app.schemas.common import ORMModel


class CustodyEventOut(ORMModel):
    id: uuid.UUID
    chain_id: uuid.UUID
    sequence_no: int
    evidence_id: uuid.UUID | None
    actor_id: uuid.UUID
    actor_role: str
    action: str
    outcome: Outcome
    occurred_at: datetime
    source_ip: str
    details_json: dict[str, Any]
    prev_event_hash: str
    event_hash: str


class ChainVerifyOut(BaseModel):
    valid: bool
    events_checked: int
    head_hash: str | None
    broken_at_event_id: uuid.UUID | None = None
    broken_at_sequence: int | None = None
    failure_type: str | None = None
