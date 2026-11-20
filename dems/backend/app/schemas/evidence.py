from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.db.models import VerifyResult
from app.schemas.common import ORMModel


class EvidenceOut(ORMModel):
    id: uuid.UUID
    case_id: uuid.UUID
    original_filename: str
    detected_mime: str
    size_bytes: int
    sha256_client: str
    sha256_server: str
    description: str | None
    source: str | None
    tags: list[str]
    acquired_at: datetime | None
    uploaded_by: uuid.UUID
    uploaded_at: datetime
    last_verified_at: datetime | None
    last_verify_result: VerifyResult | None


class IntegrityResultOut(BaseModel):
    evidence_id: uuid.UUID
    status: str
    expected_sha256: str
    actual_sha256: str | None
    detail: str
    custody_event_id: uuid.UUID
    verified_at: datetime


class EvidenceDeleteOut(BaseModel):
    id: uuid.UUID
    deleted_at: datetime
    reason: str
