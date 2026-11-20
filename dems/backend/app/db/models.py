"""SQLAlchemy 2.0 models for DEMS.

Portability: only generic SQLAlchemy types are used (Uuid, JSON, LargeBinary,
DateTime with a UTC decorator, non-native Enums with CHECK constraints), so the
schema moves from SQLite to PostgreSQL by changing DATABASE_URL. The only
dialect-specific code is the append-only trigger DDL at the bottom, which is
selected per dialect.

All relationships use ``lazy="raise"``: with async sessions, implicit lazy
loading is a bug. Load related rows explicitly (``selectinload`` / joins).
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    DDL,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    event,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# --------------------------------------------------------------------------
# Types, enums, mixins
# --------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo natively)."""

    impl = DateTime
    cache_ok = True

    def __init__(self) -> None:
        super().__init__(timezone=True)

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected; use timezone-aware UTC datetimes")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Role(enum.StrEnum):
    ADMIN = "admin"
    INVESTIGATOR = "investigator"
    AUDITOR = "auditor"


class CaseStatus(enum.StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class VerifyResult(enum.StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class Outcome(enum.StrEnum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILURE = "FAILURE"


class RefreshTokenStatus(enum.StrEnum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CustodyAction(enum.StrEnum):
    """Stored as free strings (extensible without migrations); these are the defined values."""

    INGEST = "INGEST"
    VIEW = "VIEW"
    DOWNLOAD = "DOWNLOAD"
    VERIFY = "VERIFY"
    TRANSFER = "TRANSFER"
    CASE_CREATE = "CASE_CREATE"
    CASE_CLOSE = "CASE_CLOSE"
    CASE_REOPEN = "CASE_REOPEN"
    KEY_ROTATION = "KEY_ROTATION"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    DOWNLOADED = "DOWNLOADED"
    EVIDENCE_DELETED = "EVIDENCE_DELETED"


class AuditAction(enum.StrEnum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOCKOUT = "LOCKOUT"
    LOGOUT = "LOGOUT"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    TOKEN_REUSE_DETECTED = "TOKEN_REUSE_DETECTED"
    MFA_ENROLL = "MFA_ENROLL"
    MFA_FAILURE = "MFA_FAILURE"
    USER_CREATE = "USER_CREATE"
    USER_UPDATE = "USER_UPDATE"
    USER_DEACTIVATE = "USER_DEACTIVATE"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    EVIDENCE_READ = "EVIDENCE_READ"
    EVIDENCE_UPLOAD = "EVIDENCE_UPLOAD"
    EVIDENCE_DOWNLOAD = "EVIDENCE_DOWNLOAD"
    INTEGRITY_VERIFY = "INTEGRITY_VERIFY"
    CHAIN_VERIFY = "CHAIN_VERIFY"
    AUTHZ_DENIED = "AUTHZ_DENIED"
    BACKUP_EXPORT = "BACKUP_EXPORT"
    BACKUP_RESTORE = "BACKUP_RESTORE"
    CASE_CREATE = "CASE_CREATE"
    CASE_UPDATE = "CASE_UPDATE"
    CASE_CLOSE = "CASE_CLOSE"
    CASE_DELETE = "CASE_DELETE"
    CASE_ASSIGN = "CASE_ASSIGN"
    CASE_UNASSIGN = "CASE_UNASSIGN"
    CUSTODY_READ = "CUSTODY_READ"
    EVIDENCE_DELETE = "EVIDENCE_DELETE"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    AUDIT_READ = "AUDIT_READ"
    AUDIT_VERIFY = "AUDIT_VERIFY"


def _enum(cls: type[enum.Enum], name: str, length: int = 16) -> SAEnum:
    return SAEnum(
        cls,
        name=name,
        native_enum=False,
        length=length,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
    )


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _fk_user(nullable: bool = False) -> Mapped[Any]:
    return mapped_column(Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=nullable)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow, nullable=False)


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------
class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username = lower(username)", name="username_lowercase"),
        CheckConstraint("failed_login_count >= 0", name="failed_count_nonnegative"),
        CheckConstraint("lockout_level >= 0", name="lockout_level_nonnegative"),
        Index("ix_users_role", "role"),
        Index("ix_users_is_active", "is_active"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(_enum(Role, "user_role"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lockout_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_last_counter: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    backup_codes_hash: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    password_history: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )

    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user", lazy="raise")

    def __repr__(self) -> str:  # never include credentials
        return f"<User {self.username!r} role={self.role}>"


class AuthSession(Base):
    """One login session. Its refresh tokens form a single rotation family."""

    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _fk_user()
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions", lazy="raise")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="session", lazy="raise")


class RefreshToken(Base):
    """Server-side record of an issued refresh JWT (only its SHA-256 is stored)."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_session_id", "session_id"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
        Index("ix_refresh_tokens_status", "status"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    session_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[RefreshTokenStatus] = mapped_column(
        _enum(RefreshTokenStatus, "refresh_token_status"), default=RefreshTokenStatus.ACTIVE, nullable=False
    )
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("refresh_tokens.id", ondelete="SET NULL"), nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    session: Mapped[AuthSession] = relationship(back_populates="refresh_tokens", lazy="raise")


class RevokedAccessToken(Base):
    """Denylist of access-token jtis revoked before expiry (purge rows after expires_at)."""

    __tablename__ = "revoked_access_tokens"
    __table_args__ = (Index("ix_revoked_access_tokens_expires_at", "expires_at"),)

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID | None] = _fk_user(nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(32), nullable=True)


# --------------------------------------------------------------------------
# Cases and evidence
# --------------------------------------------------------------------------
class Case(TimestampMixin, Base):
    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint("(status = 'open') OR (closed_at IS NOT NULL)", name="closed_has_timestamp"),
        Index("ix_cases_status", "status"),
        Index("ix_cases_lead_investigator_id", "lead_investigator_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(
        _enum(CaseStatus, "case_status"), default=CaseStatus.OPEN, nullable=False
    )
    lead_investigator_id: Mapped[uuid.UUID | None] = _fk_user(nullable=True)
    created_by: Mapped[uuid.UUID] = _fk_user()
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    closed_by: Mapped[uuid.UUID | None] = _fk_user(nullable=True)
    closure_manifest_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    evidence_items: Mapped[list["Evidence"]] = relationship(back_populates="case", lazy="raise")
    assignments: Mapped[list["CaseAssignment"]] = relationship(back_populates="case", lazy="raise")


class CaseAssignment(Base):
    __tablename__ = "case_assignments"
    __table_args__ = (
        Index(
            "uq_case_assignments_active",
            "case_id",
            "user_id",
            unique=True,
            sqlite_where=text("revoked_at IS NULL"),
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index("ix_case_assignments_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = _fk_user()
    assigned_by: Mapped[uuid.UUID] = _fk_user()
    assigned_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = _fk_user(nullable=True)

    case: Mapped[Case] = relationship(back_populates="assignments", lazy="raise")


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint("sha256_client = sha256_server", name="client_server_hash_match"),
        CheckConstraint("length(sha256_server) = 64", name="sha256_length"),
        CheckConstraint("size_bytes >= 0", name="size_nonnegative"),
        Index("ix_evidence_case_id", "case_id"),
        Index("ix_evidence_uploaded_by", "uploaded_by"),
        Index("ix_evidence_sha256_server", "sha256_server"),
        Index("ix_evidence_uploaded_at", "uploaded_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)  # display only, sanitized
    detected_mime: Mapped[str] = mapped_column(String(127), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_client: Mapped[str] = mapped_column(String(64), nullable=False)
    sha256_server: Mapped[str] = mapped_column(String(64), nullable=False)
    vault_path: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)  # relative to VAULT_PATH
    chunk_size: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    acquired_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    uploaded_by: Mapped[uuid.UUID] = _fk_user()
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_verify_result: Mapped[VerifyResult | None] = mapped_column(
        _enum(VerifyResult, "verify_result"), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)  # soft delete only
    deleted_by: Mapped[uuid.UUID | None] = _fk_user(nullable=True)
    delete_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    case: Mapped[Case] = relationship(back_populates="evidence_items", lazy="raise")
    keys: Mapped[list["EvidenceKey"]] = relationship(back_populates="evidence", lazy="raise")


class EvidenceKey(Base):
    """Wrapped per-file DEK. Rotation adds a new row and sets ``retired_at`` on the old one."""

    __tablename__ = "evidence_keys"
    __table_args__ = (
        UniqueConstraint("evidence_id", "key_version", name="uq_evidence_keys_evidence_version"),
        CheckConstraint("length(wrap_nonce) = 12", name="wrap_nonce_length"),
        Index(
            "uq_evidence_keys_active",
            "evidence_id",
            unique=True,
            sqlite_where=text("retired_at IS NULL"),
            postgresql_where=text("retired_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False
    )
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    recovery_wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    evidence: Mapped[Evidence] = relationship(back_populates="keys", lazy="raise")


# --------------------------------------------------------------------------
# Append-only, hash-chained ledgers
# --------------------------------------------------------------------------
class CustodyEvent(Base):
    """Per-case chain of custody. Append-only (enforced by DB triggers)."""

    __tablename__ = "custody_events"
    __table_args__ = (
        UniqueConstraint("chain_id", "sequence_no", name="uq_custody_events_chain_sequence"),
        UniqueConstraint("chain_id", "prev_event_hash", name="uq_custody_events_chain_prev"),
        UniqueConstraint("event_hash", name="uq_custody_events_event_hash"),
        CheckConstraint("sequence_no >= 1", name="sequence_positive"),
        CheckConstraint("length(event_hash) = 64 AND length(prev_event_hash) = 64", name="hash_length"),
        Index("ix_custody_events_chain_occurred", "chain_id", "occurred_at"),
        Index("ix_custody_events_evidence_id", "evidence_id"),
        Index("ix_custody_events_actor_id", "actor_id"),
        Index("ix_custody_events_action", "action"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    chain_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
    )
    sequence_no: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=True
    )
    actor_id: Mapped[uuid.UUID] = _fk_user()
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[Outcome] = mapped_column(_enum(Outcome, "custody_outcome"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    details_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    hmac_key_version: Mapped[int] = mapped_column(Integer, nullable=False)


class AuditLog(Base):
    """System-wide hash-chained audit trail. Append-only (enforced by DB triggers)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("sequence_no", name="uq_audit_log_sequence_no"),
        UniqueConstraint("prev_hash", name="uq_audit_log_prev_hash"),
        UniqueConstraint("entry_hash", name="uq_audit_log_entry_hash"),
        CheckConstraint("sequence_no >= 1", name="sequence_positive"),
        CheckConstraint("length(entry_hash) = 64 AND length(prev_hash) = 64", name="hash_length"),
        Index("ix_audit_log_occurred_at", "occurred_at"),
        Index("ix_audit_log_actor_id", "actor_id"),
        Index("ix_audit_log_action", "action"),
        Index("ix_audit_log_resource", "resource_type", "resource_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    sequence_no: Mapped[int] = mapped_column(BigInteger, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = _fk_user(nullable=True)  # NULL for unauthenticated attempts
    actor_username_attempted: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    outcome: Mapped[Outcome] = mapped_column(_enum(Outcome, "audit_outcome"), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    details_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    hmac_key_version: Mapped[int] = mapped_column(Integer, nullable=False)


# --------------------------------------------------------------------------
# Append-only enforcement (dialect-specific DDL, runs after table creation)
# --------------------------------------------------------------------------
_PG_FUNCTION = DDL(
    "CREATE OR REPLACE FUNCTION dems_forbid_mutation() RETURNS trigger AS $$ "
    "BEGIN RAISE EXCEPTION 'append-only table: UPDATE and DELETE are forbidden'; END; "
    "$$ LANGUAGE plpgsql"
)


def _install_append_only(table_name: str, model: type[Base]) -> None:
    table = model.__table__  # type: ignore[attr-defined]
    for op in ("UPDATE", "DELETE"):
        trigger = f"trg_{table_name}_no_{op.lower()}"
        sqlite_ddl = DDL(
            f"CREATE TRIGGER IF NOT EXISTS {trigger} BEFORE {op} ON {table_name} "
            f"BEGIN SELECT RAISE(ABORT, 'append-only table: {op} forbidden'); END"
        )
        pg_ddl = DDL(
            f"CREATE TRIGGER {trigger} BEFORE {op} ON {table_name} "
            f"FOR EACH ROW EXECUTE FUNCTION dems_forbid_mutation()"
        )
        event.listen(table, "after_create", sqlite_ddl.execute_if(dialect="sqlite"))
        event.listen(table, "after_create", pg_ddl.execute_if(dialect="postgresql"))
    event.listen(table, "before_create", _PG_FUNCTION.execute_if(dialect="postgresql"))


_install_append_only("custody_events", CustodyEvent)
_install_append_only("audit_log", AuditLog)
