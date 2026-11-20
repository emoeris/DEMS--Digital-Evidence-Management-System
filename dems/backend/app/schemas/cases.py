from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import CaseStatus
from app.schemas.common import ORMModel


class CaseCreate(BaseModel):
    case_number: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    lead_investigator_id: uuid.UUID | None = None


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    lead_investigator_id: uuid.UUID | None = None


class AssignmentCreate(BaseModel):
    user_id: uuid.UUID


class CaseOut(ORMModel):
    id: uuid.UUID
    case_number: str
    title: str
    description: str | None
    status: CaseStatus
    lead_investigator_id: uuid.UUID | None
    lead_investigator_username: str | None = None
    created_by: uuid.UUID
    created_at: datetime
    closed_at: datetime | None
    closed_by: uuid.UUID | None
    closure_manifest_hash: str | None


class AssignmentOut(ORMModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    user_id: uuid.UUID
    assigned_by: uuid.UUID
    assigned_at: datetime
    revoked_at: datetime | None = None
    revoked_by: uuid.UUID | None = None
