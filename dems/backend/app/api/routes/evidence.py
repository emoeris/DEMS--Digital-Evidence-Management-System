from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import StreamingResponse

from app.api.deps import CtxDep, DbDep, require_role
from app.db.models import Evidence, Role, User
from app.schemas.evidence import EvidenceDeleteOut, EvidenceOut, IntegrityResultOut
from app.services import evidence_service
from app.services.errors import bad_request

router = APIRouter(prefix="/evidence", tags=["evidence"])

_MAX_TAGS, _MAX_TAG_LEN = 20, 64
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _parse_tags(raw: str | None) -> list[str]:
    if not raw:
        return []
    tags = [t.strip() for t in raw.split(",") if t.strip()]
    if len(tags) > _MAX_TAGS or any(len(t) > _MAX_TAG_LEN or _CONTROL.search(t) for t in tags):
        raise bad_request("invalid_tags", f"At most {_MAX_TAGS} tags of {_MAX_TAG_LEN} characters each.", 422)
    return tags


@router.post("/upload", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    user: Annotated[User, Depends(require_role(Role.INVESTIGATOR))],
    db: DbDep,
    ctx: CtxDep,
    file: Annotated[UploadFile, File(description="The evidence file")],
    case_id: Annotated[uuid.UUID, Form()],
    client_sha256: Annotated[str, Form(description="SHA-256 (hex) computed in the browser before upload")],
    description: Annotated[str | None, Form(max_length=5000)] = None,
    source: Annotated[str | None, Form(max_length=255)] = None,
    tags: Annotated[str | None, Form(description="Comma-separated")] = None,
    acquired_at: Annotated[datetime | None, Form()] = None,
) -> Evidence:
    if acquired_at is not None and acquired_at.tzinfo is None:
        raise bad_request("invalid_acquired_at", "acquired_at must include a timezone offset.", 422)
    return await evidence_service.ingest(
        db, case_id=case_id, actor=user, upload=file.file, filename=file.filename, declared_mime=file.content_type,
        client_sha256=client_sha256, ctx=ctx, description=description, source=source, tags=_parse_tags(tags),
        acquired_at=acquired_at,
    )


@router.get("/{evidence_id}/metadata", response_model=EvidenceOut)
async def get_metadata(
    evidence_id: uuid.UUID,
    user: Annotated[User, Depends(require_role(Role.ADMIN, Role.INVESTIGATOR, Role.AUDITOR))],
    db: DbDep,
    ctx: CtxDep,
) -> Evidence:
    return await evidence_service.view_metadata(db, evidence_id=evidence_id, user=user, ctx=ctx)


@router.get("/{evidence_id}/download", response_class=StreamingResponse)
async def download_evidence(
    evidence_id: uuid.UUID,
    user: Annotated[User, Depends(require_role(Role.ADMIN, Role.INVESTIGATOR))],
    db: DbDep,
    ctx: CtxDep,
) -> StreamingResponse:
    """Streams decrypted bytes as an attachment. One DOWNLOADED custody event per request, committed first."""
    handle = await evidence_service.prepare_download(db, evidence_id=evidence_id, user=user, ctx=ctx)
    return StreamingResponse(
        handle.stream,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": evidence_service.content_disposition(handle.filename),
            "Content-Length": str(handle.size_bytes),
            "X-Content-Type-Options": "nosniff",
            "X-Content-SHA256": handle.sha256,
            "Cache-Control": "no-store",
        },
    )


@router.post("/{evidence_id}/verify", response_model=IntegrityResultOut)
async def verify_evidence(
    evidence_id: uuid.UUID,
    user: Annotated[User, Depends(require_role(Role.ADMIN, Role.INVESTIGATOR, Role.AUDITOR))],
    db: DbDep,
    ctx: CtxDep,
) -> IntegrityResultOut:
    result = await evidence_service.verify_integrity(db, evidence_id=evidence_id, user=user, ctx=ctx)
    return IntegrityResultOut(**result.__dict__)


@router.delete("/{evidence_id}", response_model=EvidenceDeleteOut)
async def delete_evidence(
    evidence_id: uuid.UUID,
    reason: Annotated[str, Query(min_length=3, max_length=500, description="Why the item is being removed")],
    admin: Annotated[User, Depends(require_role(Role.ADMIN))],
    db: DbDep,
    ctx: CtxDep,
) -> EvidenceDeleteOut:
    """Soft delete: the item disappears from normal views; the encrypted file and custody history remain."""
    ev = await evidence_service.soft_delete(db, evidence_id=evidence_id, admin=admin, reason=reason, ctx=ctx)
    assert ev.deleted_at is not None
    return EvidenceDeleteOut(id=ev.id, deleted_at=ev.deleted_at, reason=reason)
