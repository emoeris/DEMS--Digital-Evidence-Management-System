from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.db.models import Outcome
from app.schemas.common import ORMModel


class AuditEntryOut(ORMModel):
    id: uuid.UUID
    sequence_no: int
    occurred_at: datetime
    actor_id: uuid.UUID | None
    actor_username: str | None = None
    actor_username_attempted: str | None
    action: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    outcome: Outcome
    source_ip: str
    details_json: dict[str, Any]
    entry_hash: str
