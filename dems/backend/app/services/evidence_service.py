"""Evidence ingestion, integrity verification, download, and the custody hash chain.

Locking model
-------------
Anything that appends to a hash chain runs inside a transaction that holds the write
lock (``begin_write``): ``BEGIN IMMEDIATE`` on SQLite, plus ``SELECT ... FOR UPDATE`` on the
case row (custody chain) and a transaction-level advisory lock (audit chain) on PostgreSQL.
Slow work (hashing, encryption, disk I/O) happens *before* the lock is taken, so the lock
is held only for a few short statements.
"""
from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import os
import re
import unicodedata
import urllib.parse
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

import magic
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import crypto
from app.core.config import Settings, get_settings
from app.core.crypto import get_key_service
from app.db.models import (
    AuditAction, Case, CaseStatus, CustodyAction, CustodyEvent, Evidence, EvidenceKey, Outcome, User, VerifyResult,
    utcnow,
)
from app.db.session import begin_write
from app.services import audit_service
from app.services.access import authorize_case
from app.services.chain import ChainVerification, verify_chain_generic
from app.services.context import RequestContext
from app.services.errors import ServiceError, bad_request, conflict, not_found

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_STORED_PATH_RE = re.compile(rf"({_UUID})/({_UUID})\.enc")
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c")
_FILENAME_FORBIDDEN = frozenset('<>:"|?*')
_MAX_FILENAME_BYTES = 255
_SNIFF_BYTES = 8192


class VaultPathError(Exception):
    """A vault path was malformed or would escape the vault directory."""


# ==========================================================================
# Filename, path and MIME validation
# ==========================================================================
def sanitize_filename(raw: str | None) -> str:
    """Return a safe *display* name. Filenames are never used to build filesystem paths.

    Rejects NUL bytes and ``..`` path components outright (400); strips directory parts
    with ``PurePosixPath`` (Windows separators are normalised first); removes control and
    bidi-override characters and reserved punctuation; limits length to 255 UTF-8 bytes.
    """
    if raw is None or raw.strip() == "":
        return "unnamed"
    if "\x00" in raw:
        raise bad_request("invalid_filename", "Filename contains a NUL byte.")
    name = unicodedata.normalize("NFC", raw).replace("\\", "/")
    if any(part == ".." for part in name.split("/")):
        raise bad_request("invalid_filename", "Path traversal sequences are not allowed in filenames.")
    base = PurePosixPath(name).name
    cleaned = "".join(
        ch for ch in base
        if ch not in _BIDI_CONTROLS and ch not in _FILENAME_FORBIDDEN and unicodedata.category(ch)[0] != "C"
    )
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    if not cleaned:
        return "unnamed"
    while len(cleaned.encode("utf-8")) > _MAX_FILENAME_BYTES:
        stem, dot, ext = cleaned.rpartition(".")
        if dot and 0 < len(ext) <= 16 and stem:
            cleaned = stem[:-1].rstrip() + "." + ext if len(stem) > 1 else cleaned[:-1]
        else:
            cleaned = cleaned[:-1]
    return cleaned


def _assert_inside(root: Path, path: Path) -> None:
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise VaultPathError("path escapes the vault")
    for component in (path.parent, path):
        if component.is_symlink():
            raise VaultPathError("symbolic links are not allowed in the vault")


def vault_file_path(vault_root: Path, case_id: uuid.UUID, evidence_id: uuid.UUID) -> Path:
    """Vault location built only from server-generated UUIDs: ``<vault>/<case_id>/<evidence_id>.enc``."""
    if not isinstance(case_id, uuid.UUID) or not isinstance(evidence_id, uuid.UUID):
        raise VaultPathError("identifiers must be UUIDs")
    root = Path(vault_root).resolve()
    path = root / str(case_id) / f"{evidence_id}.enc"
    _assert_inside(root, path)
    return path


def resolve_stored_path(vault_root: Path, stored: str) -> Path:
    """Validate a ``vault_path`` read back from the database before touching the filesystem."""
    match = _STORED_PATH_RE.fullmatch(stored or "")
    if not match:
        raise VaultPathError("stored vault path is malformed")
    return vault_file_path(vault_root, uuid.UUID(match.group(1)), uuid.UUID(match.group(2)))


_ZIP_CONTAINERS = ("application/vnd.openxmlformats", "application/vnd.oasis.opendocument",
                   "application/java-archive", "application/vnd.android.package-archive", "application/epub+zip")
_TEXT_LIKE = {"application/json", "application/xml", "application/javascript", "application/x-sh",
              "application/x-ndjson", "image/svg+xml"}


def detect_mime(head: bytes) -> str:
    try:
        return magic.from_buffer(head, mime=True).lower()
    except Exception:  # libmagic failure must never become a bypass
        return "application/octet-stream"


def mime_allowed(detected: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/*") or pattern.endswith(".*"):
            if detected.startswith(pattern[:-1]):
                return True
        elif detected == pattern:
            return True
    return False


def _strict_family(expected: str) -> bool:
    return (
        expected.startswith(("image/", "audio/", "video/", "text/"))
        or expected in _TEXT_LIKE
        or expected in {"application/pdf", "application/zip", "application/gzip", "application/x-gzip"}
        or expected.startswith(_ZIP_CONTAINERS)
    )


def mime_consistent(expected: str | None, detected: str) -> bool:
    """Is a claimed type (from extension or Content-Type) compatible with the detected magic type?

    Only enforced for families where a mismatch is a meaningful spoofing signal (images, audio,
    video, text, PDF, archives and Office containers). Other claims are left to the allow-list.
    """
    if not expected or expected == "application/octet-stream" or not _strict_family(expected):
        return True
    expected, detected = expected.lower(), detected.lower()
    if expected == detected:
        return True
    top = expected.split("/", 1)[0]
    if top in {"image", "audio", "video"} and detected.split("/", 1)[0] == top:
        return True
    if expected.startswith(_ZIP_CONTAINERS) or expected == "application/zip":
        return detected == "application/zip" or detected.startswith(_ZIP_CONTAINERS)
    if top == "text" or expected in _TEXT_LIKE:
        return detected.startswith("text/") or detected in _TEXT_LIKE
    if expected in {"application/gzip", "application/x-gzip"}:
        return detected in {"application/gzip", "application/x-gzip"}
    return False


# ==========================================================================
# Custody chain
# ==========================================================================
def _custody_hash_for(row: CustodyEvent) -> str:
    return crypto.compute_custody_event_hash(
        chain_id=row.chain_id, sequence_no=row.sequence_no, prev_event_hash=row.prev_event_hash,
        evidence_id=row.evidence_id, actor_id=row.actor_id, actor_role=row.actor_role, action=row.action,
        outcome=row.outcome.value, occurred_at=row.occurred_at, source_ip=row.source_ip,
        details_hash_hex=crypto.details_hash(row.details_json),  # recomputed, not trusted from the row
    )


async def chain_append(
    db: AsyncSession,
    *,
    case_id: uuid.UUID,
    actor: User,
    action: CustodyAction | str,
    outcome: Outcome,
    ctx: RequestContext,
    evidence_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> CustodyEvent:
    """Append one immutable event to the case's custody chain.

    ``prev_event_hash`` is the ``event_hash`` of the latest event for the case, or the case's
    genesis hash when it is the first. The caller commits (so the event shares a transaction with
    the action it records). Concurrent appends are serialised by the write lock; the unique
    constraints on (chain_id, sequence_no) and (chain_id, prev_event_hash) make a fork impossible
    even if a lock were ever bypassed.
    """
    await begin_write(db)
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(select(Case.id).where(Case.id == case_id).with_for_update())

    last = (
        await db.execute(
            select(CustodyEvent).where(CustodyEvent.chain_id == case_id).order_by(CustodyEvent.sequence_no.desc()).limit(1)
        )
    ).scalar_one_or_none()
    sequence_no = 1 if last is None else last.sequence_no + 1
    prev_hash = crypto.genesis_hash(case_id) if last is None else last.event_hash

    clean = audit_service._normalise_details(details)
    dhash = crypto.details_hash(clean)
    occurred_at = utcnow()
    event_hash = crypto.compute_custody_event_hash(
        chain_id=case_id, sequence_no=sequence_no, prev_event_hash=prev_hash, evidence_id=evidence_id,
        actor_id=actor.id, actor_role=actor.role.value, action=str(action), outcome=outcome.value,
        occurred_at=occurred_at, source_ip=ctx.ip, details_hash_hex=dhash,
    )
    keys = get_key_service()
    event = CustodyEvent(
        chain_id=case_id, sequence_no=sequence_no, evidence_id=evidence_id, actor_id=actor.id,
        actor_role=actor.role.value, action=str(action), outcome=outcome, occurred_at=occurred_at,
        source_ip=ctx.ip, details_json=clean, details_hash=dhash, prev_event_hash=prev_hash,
        event_hash=event_hash, event_hmac=keys.audit_hmac(event_hash), hmac_key_version=keys.hmac_key_version,
    )
    db.add(event)
    await db.flush()
    return event


async def verify_chain(db: AsyncSession, case_id: uuid.UUID) -> ChainVerification:
    """Recompute every hash of the case's chain. Returns ``valid`` and, if broken, the first bad event.

    Result fields: ``valid``, ``broken_at_event_id`` (id of the first failing event; for a deleted
    row this is the event that follows the gap), ``broken_at_sequence``, ``failure_type``.
    """
    return await verify_chain_generic(
        db, CustodyEvent, where=[CustodyEvent.chain_id == case_id], prev_attr="prev_event_hash",
        hash_attr="event_hash", hmac_attr="event_hmac", recompute=_custody_hash_for,
        genesis=crypto.genesis_hash(case_id),
    )


# ==========================================================================
# Ingestion
# ==========================================================================
def _hash_and_sniff(fh: BinaryIO, max_bytes: int) -> tuple[str, int, bytes]:
    fh.seek(0)
    head = fh.read(_SNIFF_BYTES)
    fh.seek(0)
    sha = hashlib.sha256()
    total = 0
    while chunk := fh.read(1024 * 1024):
        total += len(chunk)
        if total > max_bytes:
            raise crypto.SizeLimitExceeded("file exceeds the maximum allowed size")
        sha.update(chunk)
    fh.seek(0)
    return sha.hexdigest(), total, head


async def _reject(
    db: AsyncSession, *, actor: User, case_id: uuid.UUID, ctx: RequestContext, status: int, code: str,
    message: str, details: dict[str, Any] | None = None,
) -> ServiceError:
    """Audit a refused upload (committed on its own) and return the error to raise."""
    await audit_service.record(
        db, action=AuditAction.EVIDENCE_REJECTED, outcome=Outcome.FAILURE, ctx=ctx, actor_id=actor.id,
        resource_type="case", resource_id=case_id, details={"code": code, **(details or {})},
    )
    await db.commit()
    return ServiceError(status, code, message)


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


async def ingest(
    db: AsyncSession,
    *,
    case_id: uuid.UUID,
    actor: User,
    upload: BinaryIO,
    filename: str | None,
    declared_mime: str | None,
    client_sha256: str,
    ctx: RequestContext,
    description: str | None = None,
    source: str | None = None,
    tags: list[str] | None = None,
    acquired_at: datetime | None = None,
    settings: Settings | None = None,
) -> Evidence:
    """Validate, encrypt and persist one evidence file atomically.

    Order: authorise -> validate name/hash/size/type -> encrypt into the vault (no DB lock) ->
    one transaction (case locked) inserting the evidence row, wrapped DEK, INGEST custody event
    and audit entry. If anything fails the transaction is rolled back and the vault file removed.
    """
    s = settings or get_settings()
    case = await authorize_case(db, case_id, actor, "write")
    if case.status != CaseStatus.OPEN:
        raise await _reject(db, actor=actor, case_id=case_id, ctx=ctx, status=409, code="case_closed",
                            message="This case is closed; no new evidence can be added.")

    client_hash = (client_sha256 or "").strip().lower()
    if not _SHA256_RE.fullmatch(client_hash):
        raise await _reject(db, actor=actor, case_id=case_id, ctx=ctx, status=422, code="invalid_client_hash",
                            message="client_sha256 must be a 64-character hexadecimal SHA-256.")
    try:
        safe_name = sanitize_filename(filename)
    except ServiceError as exc:
        raise await _reject(db, actor=actor, case_id=case_id, ctx=ctx, status=exc.status_code, code=exc.code,
                            message=exc.message) from None

    try:
        server_hash, size, head = await asyncio.to_thread(_hash_and_sniff, upload, s.upload_max_bytes)
    except crypto.SizeLimitExceeded:
        raise await _reject(db, actor=actor, case_id=case_id, ctx=ctx, status=413, code="file_too_large",
                            message=f"File exceeds the {s.upload_max_bytes}-byte limit.",
                            details={"filename": safe_name}) from None
    if size == 0:
        raise await _reject(db, actor=actor, case_id=case_id, ctx=ctx, status=400, code="empty_file",
                            message="Empty files cannot be ingested.", details={"filename": safe_name})
    if not crypto.constant_time_equals(server_hash, client_hash):
        raise await _reject(db, actor=actor, case_id=case_id, ctx=ctx, status=422, code="hash_mismatch",
                            message="The uploaded bytes do not match the client-computed SHA-256.",
                            details={"filename": safe_name, "client_sha256": client_hash, "server_sha256": server_hash})

    detected = detect_mime(head)
    guessed = mimetypes.guess_type(safe_name)[0]
    reasons = []
    if not mime_allowed(detected, s.allowed_mime_list):
        reasons.append("detected type is not on the allow-list")
    if not mime_consistent(guessed, detected):
        reasons.append("file extension does not match the file content")
    if not mime_consistent((declared_mime or "").split(";")[0].strip().lower() or None, detected):
        reasons.append("declared Content-Type does not match the file content")
    if reasons:
        raise await _reject(
            db, actor=actor, case_id=case_id, ctx=ctx, status=415, code="unsupported_media_type",
            message="File type rejected: " + "; ".join(reasons) + ".",
            details={"filename": safe_name, "detected_mime": detected, "declared_mime": declared_mime},
        )

    evidence_id = uuid.uuid4()
    dest = vault_file_path(s.vault_path, case.id, evidence_id)
    context = crypto.file_context(case.id, evidence_id)
    dek = crypto.generate_dek()
    keys = get_key_service()
    wrapped = keys.wrap_dek(dek, evidence_id=evidence_id)

    written = False
    try:
        result = await crypto.encrypt_file_atomic_async(
            upload, dest, dek, context=context, chunk_size=s.chunk_size, max_bytes=s.upload_max_bytes
        )
        written = True
        if os.name == "posix":
            os.chmod(dest, 0o600)
            if dest.stat().st_mode & 0o077:
                raise RuntimeError("vault file permissions are too permissive")
        if result.plaintext_sha256 != server_hash:  # the source changed between the two passes
            raise RuntimeError("plaintext changed during ingestion")

        await begin_write(db)
        locked_case = (
            await db.execute(select(Case).where(Case.id == case.id).with_for_update().execution_options(populate_existing=True))
        ).scalar_one()
        if locked_case.status != CaseStatus.OPEN:
            raise conflict("case_closed", "This case was closed while the upload was in progress.")

        evidence = Evidence(
            id=evidence_id, case_id=case.id, original_filename=safe_name, detected_mime=detected, size_bytes=size,
            sha256_client=client_hash, sha256_server=server_hash, vault_path=f"{case.id}/{evidence_id}.enc",
            chunk_size=result.chunk_size, ciphertext_size=result.ciphertext_size, description=description,
            source=source, tags=list(tags or []), acquired_at=acquired_at, uploaded_by=actor.id,
        )
        db.add(evidence)
        await db.flush()
        db.add(EvidenceKey(
            evidence_id=evidence_id, key_version=wrapped.key_version, wrapped_dek=wrapped.wrapped_dek,
            wrap_nonce=wrapped.wrap_nonce,
        ))
        await db.flush()
        await chain_append(
            db, case_id=case.id, actor=actor, action=CustodyAction.INGEST, outcome=Outcome.SUCCESS, ctx=ctx,
            evidence_id=evidence_id,
            details={"filename": safe_name, "mime": detected, "size_bytes": size, "sha256": server_hash,
                     "client_sha256": client_hash, "key_version": wrapped.key_version},
        )
        await audit_service.record(
            db, action=AuditAction.EVIDENCE_UPLOAD, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=actor.id,
            resource_type="evidence", resource_id=evidence_id,
            details={"case_id": str(case.id), "sha256": server_hash, "size_bytes": size},
        )
        await db.commit()
        return evidence
    except BaseException:
        await db.rollback()
        if written or dest.exists():
            _unlink_quietly(dest)
        raise
    finally:
        del dek


# ==========================================================================
# Loading and authorisation helpers
# ==========================================================================
async def _load_evidence(
    db: AsyncSession, evidence_id: uuid.UUID, user: User, level: str, *, include_deleted: bool = False
) -> tuple[Evidence, Case]:
    evidence = await db.get(Evidence, evidence_id)
    if evidence is None or (evidence.deleted_at is not None and not include_deleted):
        raise not_found("Evidence")
    case = await authorize_case(db, evidence.case_id, user, level)  # type: ignore[arg-type]
    return evidence, case


async def _unwrap_dek(db: AsyncSession, evidence: Evidence) -> bytes:
    key_row = (
        await db.execute(
            select(EvidenceKey).where(EvidenceKey.evidence_id == evidence.id, EvidenceKey.retired_at.is_(None))
        )
    ).scalar_one_or_none()
    if key_row is None:
        raise ServiceError(500, "key_missing", "No active key is recorded for this evidence item.")
    try:
        return get_key_service().unwrap_dek(
            key_row.wrapped_dek, key_row.wrap_nonce, evidence_id=evidence.id, key_version=key_row.key_version
        )
    except crypto.CryptoError:
        raise ServiceError(500, "key_unwrap_failed", "The evidence key could not be unwrapped.") from None


def _path_for(evidence: Evidence, settings: Settings) -> Path:
    try:
        return resolve_stored_path(settings.vault_path, evidence.vault_path)
    except VaultPathError:
        raise ServiceError(500, "vault_path_invalid", "The stored vault path failed validation.") from None


# ==========================================================================
# Metadata view
# ==========================================================================
async def view_metadata(db: AsyncSession, *, evidence_id: uuid.UUID, user: User, ctx: RequestContext) -> Evidence:
    evidence, case = await _load_evidence(db, evidence_id, user, "metadata")
    await chain_append(db, case_id=case.id, actor=user, action=CustodyAction.VIEW, outcome=Outcome.SUCCESS,
                       ctx=ctx, evidence_id=evidence.id, details={"view": "metadata"})
    await audit_service.record(db, action=AuditAction.EVIDENCE_READ, outcome=Outcome.SUCCESS, ctx=ctx,
                               actor_id=user.id, resource_type="evidence", resource_id=evidence.id)
    await db.commit()
    return evidence


# ==========================================================================
# Integrity verification
# ==========================================================================
@dataclass(frozen=True)
class IntegrityResult:
    evidence_id: uuid.UUID
    status: str  # "pass" | "fail" | "error"
    expected_sha256: str
    actual_sha256: str | None
    detail: str
    custody_event_id: uuid.UUID
    verified_at: datetime


async def _run_integrity_check(db: AsyncSession, evidence: Evidence, dek: bytes, s: Settings) -> crypto.VerifyOutcome:
    path = _path_for(evidence, s)
    try:
        actual_size = (await asyncio.to_thread(path.stat)).st_size
    except OSError:
        return crypto.VerifyOutcome("error", None, "encrypted file is missing or unreadable")
    if actual_size != evidence.ciphertext_size:
        return crypto.VerifyOutcome("fail", None, "ciphertext size differs from the recorded size")
    return await crypto.verify_encrypted_file_async(
        path, dek, context=crypto.file_context(evidence.case_id, evidence.id),
        expected_sha256_hex=evidence.sha256_server,
    )


async def verify_integrity(db: AsyncSession, *, evidence_id: uuid.UUID, user: User, ctx: RequestContext,
                           settings: Settings | None = None) -> IntegrityResult:
    """Decrypt the vault file (checking every GCM tag), re-hash it, compare with the recorded SHA-256,
    and append an INTEGRITY_VERIFIED or INTEGRITY_FAILED custody event."""
    s = settings or get_settings()
    evidence, case = await _load_evidence(db, evidence_id, user, "metadata")
    dek = await _unwrap_dek(db, evidence)
    try:
        outcome = await _run_integrity_check(db, evidence, dek, s)
    finally:
        del dek

    passed = outcome.status == "pass"
    event = await chain_append(
        db, case_id=case.id, actor=user,
        action=CustodyAction.INTEGRITY_VERIFIED if passed else CustodyAction.INTEGRITY_FAILED,
        outcome=Outcome.SUCCESS if passed else Outcome.FAILURE, ctx=ctx, evidence_id=evidence.id,
        details={"status": outcome.status, "expected_sha256": evidence.sha256_server,
                 "actual_sha256": outcome.actual_sha256, "detail": outcome.detail},
    )
    evidence.last_verified_at = event.occurred_at
    evidence.last_verify_result = VerifyResult(outcome.status)
    await audit_service.record(
        db, action=AuditAction.INTEGRITY_VERIFY, outcome=Outcome.SUCCESS if passed else Outcome.FAILURE, ctx=ctx,
        actor_id=user.id, resource_type="evidence", resource_id=evidence.id, details={"status": outcome.status},
    )
    await db.commit()
    return IntegrityResult(evidence.id, outcome.status, evidence.sha256_server, outcome.actual_sha256,
                           outcome.detail, event.id, event.occurred_at)


# ==========================================================================
# Download
# ==========================================================================
@dataclass
class DownloadHandle:
    evidence: Evidence
    filename: str
    size_bytes: int
    sha256: str
    stream: AsyncIterator[bytes]


async def _iter_plaintext(path: Path, dek: bytes, context: bytes) -> AsyncIterator[bytes]:
    handle = await asyncio.to_thread(open, path, "rb")
    try:
        chunks = crypto.iter_decrypt(handle, dek, context=context)
        while True:
            chunk = await asyncio.to_thread(next, chunks, None)
            if chunk is None:
                return
            yield chunk
    finally:
        await asyncio.to_thread(handle.close)


async def prepare_download(db: AsyncSession, *, evidence_id: uuid.UUID, user: User, ctx: RequestContext,
                           settings: Settings | None = None) -> DownloadHandle:
    """Authorise, (optionally) verify integrity first, log ONE DOWNLOADED custody event, return a stream.

    The custody event and audit entry are committed *before* any bytes are sent, so access can
    never go unrecorded, and the database transaction is closed before streaming begins.
    """
    s = settings or get_settings()
    evidence, case = await _load_evidence(db, evidence_id, user, "content")
    dek = await _unwrap_dek(db, evidence)
    try:
        if s.verify_before_download:
            outcome = await _run_integrity_check(db, evidence, dek, s)
            if outcome.status != "pass":
                await chain_append(
                    db, case_id=case.id, actor=user, action=CustodyAction.INTEGRITY_FAILED, outcome=Outcome.FAILURE,
                    ctx=ctx, evidence_id=evidence.id,
                    details={"status": outcome.status, "trigger": "pre-download", "detail": outcome.detail},
                )
                await audit_service.record(
                    db, action=AuditAction.INTEGRITY_VERIFY, outcome=Outcome.FAILURE, ctx=ctx, actor_id=user.id,
                    resource_type="evidence", resource_id=evidence.id, details={"trigger": "pre-download"},
                )
                await db.commit()
                raise conflict("integrity_failure", "Integrity verification failed; the download was refused.")

        await chain_append(
            db, case_id=case.id, actor=user, action=CustodyAction.DOWNLOADED, outcome=Outcome.SUCCESS, ctx=ctx,
            evidence_id=evidence.id,
            details={"sha256": evidence.sha256_server, "size_bytes": evidence.size_bytes, "filename": evidence.original_filename},
        )
        await audit_service.record(
            db, action=AuditAction.EVIDENCE_DOWNLOAD, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=user.id,
            resource_type="evidence", resource_id=evidence.id, details={"sha256": evidence.sha256_server},
        )
        await db.commit()
    except BaseException:
        del dek
        raise

    stream = _iter_plaintext(_path_for(evidence, s), dek, crypto.file_context(evidence.case_id, evidence.id))
    return DownloadHandle(evidence, evidence.original_filename, evidence.size_bytes, evidence.sha256_server, stream)


def content_disposition(filename: str) -> str:
    """RFC 6266 / 5987 attachment header, safe against header injection."""
    ascii_name = re.sub(r'[^A-Za-z0-9._ -]', "_", filename.encode("ascii", "replace").decode("ascii")) or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(filename, safe='')}"


# ==========================================================================
# Soft delete
# ==========================================================================
async def soft_delete(db: AsyncSession, *, evidence_id: uuid.UUID, admin: User, reason: str, ctx: RequestContext) -> Evidence:
    """Mark evidence deleted. The encrypted file and wrapped key are retained for the record."""
    evidence = await db.get(Evidence, evidence_id)
    if evidence is None or evidence.deleted_at is not None:
        raise not_found("Evidence")
    await begin_write(db)
    case = (
        await db.execute(select(Case).where(Case.id == evidence.case_id).with_for_update().execution_options(populate_existing=True))
    ).scalar_one()
    evidence = await db.get(Evidence, evidence_id, populate_existing=True)
    if evidence is None or evidence.deleted_at is not None:
        raise not_found("Evidence")
    if case.status != CaseStatus.OPEN:
        raise conflict("case_closed", "Evidence in a closed case cannot be deleted.")
    evidence.deleted_at = utcnow()
    evidence.deleted_by = admin.id
    evidence.delete_reason = reason
    await chain_append(
        db, case_id=case.id, actor=admin, action=CustodyAction.EVIDENCE_DELETED, outcome=Outcome.SUCCESS, ctx=ctx,
        evidence_id=evidence.id, details={"reason": reason, "sha256": evidence.sha256_server, "soft_delete": True},
    )
    await audit_service.record(
        db, action=AuditAction.EVIDENCE_DELETE, outcome=Outcome.SUCCESS, ctx=ctx, actor_id=admin.id,
        resource_type="evidence", resource_id=evidence.id, details={"reason": reason},
    )
    await db.commit()
    return evidence
