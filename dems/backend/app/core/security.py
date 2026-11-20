"""Authentication primitives: Argon2id passwords, JWTs, TOTP MFA, backup codes.

Design notes
* Passwords: Argon2id via passlib; unknown users are verified against a dummy
  hash so response time does not reveal whether an account exists.
* JWTs: access and refresh tokens are signed with *different* keys derived
  from SECRET_KEY (prevents token-type confusion), the algorithm is pinned,
  and iss/aud/exp/nbf/iat/jti/sub are all required on decode.
* TOTP: replay protection via a stored last-used time-step counter.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Literal, Sequence

import pyotp
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext
from passlib.exc import PasswordSizeError, UnknownHashError

from app.core.config import Settings, get_settings
from app.core.crypto import get_key_service

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
TOTP_DIGITS = 6
TOTP_INTERVAL = 30
BACKUP_CODE_COUNT = 10
_BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_MAX_TOKEN_LENGTH = 4096


# ==========================================================================
# Passwords
# ==========================================================================
@lru_cache
def _pwd_context() -> CryptContext:
    s = get_settings()
    return CryptContext(
        schemes=["argon2"],
        deprecated="auto",
        argon2__type="ID",
        argon2__time_cost=s.password_time_cost,
        argon2__memory_cost=s.password_memory_kib,
        argon2__parallelism=s.password_parallelism,
        argon2__salt_size=16,
        argon2__digest_size=32,
    )


@lru_cache
def _dummy_hash() -> str:
    return _pwd_context().hash(secrets.token_urlsafe(24))


def hash_password(password: str) -> str:
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("password too long")
    return _pwd_context().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if len(password) > MAX_PASSWORD_LENGTH:
        _pwd_context().verify("x", _dummy_hash())  # keep timing similar
        return False
    try:
        return _pwd_context().verify(password, password_hash)
    except (ValueError, TypeError, UnknownHashError, PasswordSizeError):
        return False


def authenticate_password(password: str, stored_hash: str | None) -> tuple[bool, bool]:
    """Verify in (near) constant time whether or not the account exists.

    Returns ``(is_valid, needs_rehash)``. Pass ``None`` for unknown users.
    """
    if stored_hash is None:
        verify_password(password, _dummy_hash())
        return False, False
    ok = verify_password(password, stored_hash)
    return ok, ok and _pwd_context().needs_update(stored_hash)


def password_needs_rehash(password_hash: str) -> bool:
    return _pwd_context().needs_update(password_hash)


_BUILTIN_COMMON = frozenset(
    {
        "password1234", "password12345", "passwordpassword", "123456789012", "1234567890123",
        "qwertyuiopas", "qwertyuiop12", "letmein12345", "welcome12345", "changeme1234",
        "administrator", "iloveyou1234", "abcdefghijkl", "adminadmin12", "000000000000",
        "111111111111", "aaaaaaaaaaaa", "password!234", "p@ssw0rd1234", "trustno1trustno1",
    }
)


@lru_cache
def _common_passwords() -> frozenset[str]:
    path = get_settings().common_passwords_path
    if path is None:
        return _BUILTIN_COMMON
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return _BUILTIN_COMMON
    return _BUILTIN_COMMON | frozenset(line.strip().casefold() for line in lines if line.strip())


@dataclass(frozen=True)
class PolicyResult:
    valid: bool
    errors: tuple[str, ...]


def validate_password_policy(
    password: str,
    *,
    username: str | None = None,
    email: str | None = None,
    history_hashes: Sequence[str] = (),
) -> PolicyResult:
    errors: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters long.")
    if password and not password.strip():
        errors.append("Password must not consist only of whitespace.")
    if len(set(password)) < 5 and len(password) >= MIN_PASSWORD_LENGTH:
        errors.append("Password is too repetitive.")
    folded = password.casefold()
    if folded in _common_passwords():
        errors.append("Password is too common or appears in breach lists.")
    for ident in (username, email.split("@")[0] if email else None):
        if ident and len(ident) >= 3 and ident.casefold() in folded:
            errors.append("Password must not contain your username or email name.")
            break
    if not errors:  # the history check is expensive, so only run it for otherwise valid passwords
        for old in history_hashes:
            if verify_password(password, old):
                errors.append("Password was used recently; choose a different one.")
                break
    return PolicyResult(not errors, tuple(errors))


# ==========================================================================
# Tokens (JWT)
# ==========================================================================
TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Token is invalid for any reason (message is deliberately generic)."""


class TokenExpiredError(TokenError):
    """Token signature is valid but it has expired."""


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    token_type: TokenType
    jti: str
    session_id: str
    issued_at: datetime
    expires_at: datetime
    role: str | None
    mfa_verified: bool


def _signing_key(token_type: TokenType, settings: Settings) -> bytes:
    root = settings.secret_key.get_secret_value().encode("utf-8")
    return hmac.new(root, b"dems/v1/jwt/" + token_type.encode(), hashlib.sha256).digest()


def _issue(
    token_type: TokenType,
    ttl: int,
    claims: dict[str, object],
    now: datetime | None,
    settings: Settings,
) -> IssuedToken:
    issued = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    expires = issued + timedelta(seconds=ttl)
    jti = uuid.uuid4().hex
    payload: dict[str, object] = {
        **claims,
        "type": token_type,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": jti,
    }
    token = jwt.encode(payload, _signing_key(token_type, settings), algorithm=settings.jwt_algorithm)
    return IssuedToken(token=token, jti=jti, expires_at=expires)


def create_access_token(
    *,
    user_id: uuid.UUID | str,
    role: str,
    session_id: uuid.UUID | str,
    mfa_verified: bool = False,
    now: datetime | None = None,
) -> IssuedToken:
    s = get_settings()
    return _issue(
        "access",
        s.access_token_ttl,
        {"sub": str(user_id), "role": role, "sid": str(session_id), "mfa": bool(mfa_verified)},
        now,
        s,
    )


def create_refresh_token(
    *, user_id: uuid.UUID | str, session_id: uuid.UUID | str, now: datetime | None = None
) -> IssuedToken:
    s = get_settings()
    return _issue("refresh", s.refresh_token_ttl, {"sub": str(user_id), "sid": str(session_id)}, now, s)


def decode_token(token: str, *, expected_type: TokenType) -> TokenClaims:
    s = get_settings()
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        raise TokenError("invalid token")
    try:
        payload = jwt.decode(
            token,
            _signing_key(expected_type, s),
            algorithms=[s.jwt_algorithm],
            audience=s.jwt_audience,
            issuer=s.jwt_issuer,
            options={
                "require_exp": True, "require_iat": True, "require_nbf": True,
                "require_iss": True, "require_aud": True, "require_sub": True,
                "require_jti": True, "leeway": 5,
            },
        )
    except ExpiredSignatureError:
        raise TokenExpiredError("token expired") from None
    except JWTError:
        raise TokenError("invalid token") from None

    if payload.get("type") != expected_type:
        raise TokenError("invalid token")
    sid = payload.get("sid")
    if not isinstance(sid, str) or not sid or not isinstance(payload.get("jti"), str):
        raise TokenError("invalid token")
    return TokenClaims(
        subject=str(payload["sub"]),
        token_type=expected_type,
        jti=payload["jti"],
        session_id=sid,
        issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=timezone.utc),
        expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc),
        role=payload.get("role") if expected_type == "access" else None,
        mfa_verified=bool(payload.get("mfa", False)),
    )


def hash_token(token: str) -> str:
    """SHA-256 hex digest used to store refresh tokens (never store the token itself)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ==========================================================================
# TOTP (RFC 6238) and backup codes
# ==========================================================================
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account_name: str, issuer: str | None = None) -> str:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).provisioning_uri(
        name=account_name, issuer_name=issuer or get_settings().app_name
    )


def current_totp_counter(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // TOTP_INTERVAL)


def verify_totp(
    secret: str, code: str, *, last_used_counter: int = 0, now: float | None = None
) -> int | None:
    """Return the matched time-step counter, or ``None`` if invalid or replayed.

    Accepts the previous, current and next step (+/- 30 s drift). A counter at or
    below ``last_used_counter`` is rejected so a code can only be used once;
    persist the returned counter on the user record.
    """
    cleaned = re.sub(r"\s+", "", code or "")
    if not re.fullmatch(rf"\d{{{TOTP_DIGITS}}}", cleaned):
        return None
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    current = current_totp_counter(now)
    matched: int | None = None
    for counter in (current - 1, current, current + 1):  # always evaluate all three
        if hmac.compare_digest(totp.generate_otp(counter), cleaned) and counter > last_used_counter:
            matched = counter
    return matched


def encrypt_totp_secret(secret: str) -> bytes:
    return get_key_service().seal(secret.encode("ascii"), purpose="totp-secret")


def decrypt_totp_secret(blob: bytes) -> str:
    return get_key_service().unseal(blob, purpose="totp-secret").decode("ascii")


def _normalize_backup_code(code: str) -> str:
    return re.sub(r"[\s\-]", "", code or "").upper()


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> tuple[list[str], list[str]]:
    """Return ``(display_codes, hashes)``. Show the display codes once; store the hashes."""
    display: list[str] = []
    hashes: list[str] = []
    for _ in range(count):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(10))
        display.append(f"{raw[:5]}-{raw[5:]}")
        hashes.append(hash_password(raw))
    return display, hashes


def verify_backup_code(code: str, hashes: Sequence[str]) -> int | None:
    """Index of the matching hash (caller must delete it: codes are single use)."""
    normalized = _normalize_backup_code(code)
    if len(normalized) != 10:
        return None
    match: int | None = None
    for i, h in enumerate(hashes):  # check all entries to avoid a position-dependent timing signal
        if verify_password(normalized, h) and match is None:
            match = i
    return match
