"""Core cryptography for DEMS.

Key hierarchy (see Phase 1, section 2.4)::

    passphrase --Argon2id(salt)--> root secret (32 B)
        --HKDF-SHA256--> KEK         (wraps per-file DEKs)
                         audit key   (HMAC of audit / custody entries)
                         TOTP key    (seals TOTP secrets in the database)
                         backup key  (signs backup manifests)

Evidence files are encrypted in 1 MiB chunks with AES-256-GCM under a unique
per-file DEK. Every chunk uses its own random 96-bit nonce from
``secrets.token_bytes(12)`` (uniqueness inside a file is additionally enforced
in code), and its associated data binds the file header, the evidence context,
the chunk index and a "final chunk" flag, so reordering, swapping and
truncation are all detected.

Nothing in this module logs, prints or repr()s key material.
"""
from __future__ import annotations

import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import tempfile
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Literal

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import Settings, get_settings

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
MIN_SALT_LEN = 16
MIN_PASSPHRASE_LEN = 12

FILE_MAGIC = b"DEMS"
FILE_FORMAT_VERSION = 1
_HEADER_FMT = ">4sBI"  # magic, version, chunk_size
HEADER_LEN = struct.calcsize(_HEADER_FMT)
DEFAULT_CHUNK_SIZE = 1024 * 1024
MIN_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024

_LABEL_KEK = b"dems/v1/kek"
_LABEL_AUDIT = b"dems/v1/audit-hmac"
_LABEL_TOTP = b"dems/v1/totp-seal"
_LABEL_BACKUP = b"dems/v1/backup-sign"
_CANARY_PLAINTEXT = b"DEMS-KEY-CANARY-V1"
_CANARY_AAD = b"dems/v1/canary"

CUSTODY_DOMAIN = b"DEMS-CUSTODY-V1"
AUDIT_DOMAIN = b"DEMS-AUDIT-V1"
AUDIT_CHAIN_ID = "dems-audit-log"


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------
class CryptoError(Exception):
    """Base class for cryptographic failures."""


class DecryptionError(CryptoError):
    """Authentication failed, data truncated, reordered or otherwise corrupt."""


class InvalidPassphraseError(CryptoError):
    """The supplied passphrase does not match the stored key configuration."""


class KeyConfigError(CryptoError):
    """The key configuration is missing, malformed or unusable."""


class KeyServiceNotInitialized(CryptoError):
    """Key material was requested before the key service was unlocked."""


class SizeLimitExceeded(CryptoError):
    """Plaintext exceeded the configured maximum size while streaming."""


# --------------------------------------------------------------------------
# Small primitives
# --------------------------------------------------------------------------
def generate_dek() -> bytes:
    """New random 256-bit data-encryption key."""
    return secrets.token_bytes(KEY_LEN)


def new_nonce() -> bytes:
    """New random 96-bit GCM nonce."""
    return secrets.token_bytes(NONCE_LEN)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt one message. Returns ``(nonce, ciphertext_with_tag)``."""
    _require_key(key)
    nonce = new_nonce()
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    _require_key(key)
    if len(nonce) != NONCE_LEN:
        raise DecryptionError("invalid nonce length")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("authentication failed") from None


def hmac_sha256_hex(key: bytes, data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac_hex(key: bytes, data: bytes | str, mac_hex: str) -> bool:
    return hmac.compare_digest(hmac_sha256_hex(key, data), mac_hex.lower())


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def sha256_stream(src: BinaryIO, block: int = 1024 * 1024) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    while chunk := src.read(block):
        h.update(chunk)
        total += len(chunk)
    return h.hexdigest(), total


def _require_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise CryptoError("key must be exactly 32 bytes")


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_cost_kib: int
    parallelism: int

    def __post_init__(self) -> None:
        if self.time_cost < 1 or self.parallelism < 1:
            raise ValueError("invalid Argon2 parameters")
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ValueError("Argon2 memory cost must be >= 8 * parallelism KiB")

    @classmethod
    def from_settings(cls, s: Settings) -> "KdfParams":
        return cls(s.kdf_time_cost, s.kdf_memory_kib, s.kdf_parallelism)


@dataclass(frozen=True, repr=False)
class DerivedKeys:
    kek: bytes
    audit_key: bytes
    totp_key: bytes
    backup_key: bytes

    def __repr__(self) -> str:  # never reveal key bytes
        return "DerivedKeys(<redacted>)"


def derive_root_secret(passphrase: str | bytes, salt: bytes, params: KdfParams) -> bytes:
    """Argon2id(passphrase, salt) -> 32-byte root secret."""
    if len(salt) < MIN_SALT_LEN:
        raise ValueError("salt must be at least 16 bytes")
    secret = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def _hkdf(root: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=label).derive(root)


def derive_keys(passphrase: str | bytes, salt: bytes, params: KdfParams) -> DerivedKeys:
    root = derive_root_secret(passphrase, salt, params)
    return DerivedKeys(
        kek=_hkdf(root, _LABEL_KEK),
        audit_key=_hkdf(root, _LABEL_AUDIT),
        totp_key=_hkdf(root, _LABEL_TOTP),
        backup_key=_hkdf(root, _LABEL_BACKUP),
    )


def derive_kek(passphrase: str | bytes, salt: bytes, params: KdfParams) -> bytes:
    """Derive only the 32-byte Key Encryption Key."""
    return derive_keys(passphrase, salt, params).kek


# --------------------------------------------------------------------------
# Persistent (non-secret) key configuration: salt, KDF params, canary
# --------------------------------------------------------------------------
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


@dataclass(frozen=True)
class KeyConfig:
    salt: bytes
    params: KdfParams
    key_version: int
    canary_nonce: bytes
    canary_ct: bytes

    def to_json(self) -> str:
        return json.dumps(
            {
                "format": 1,
                "kdf": "argon2id",
                "salt": _b64(self.salt),
                "time_cost": self.params.time_cost,
                "memory_cost_kib": self.params.memory_cost_kib,
                "parallelism": self.params.parallelism,
                "key_version": self.key_version,
                "canary_nonce": _b64(self.canary_nonce),
                "canary_ct": _b64(self.canary_ct),
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> "KeyConfig":
        try:
            d = json.loads(text)
            if d.get("format") != 1 or d.get("kdf") != "argon2id":
                raise KeyConfigError("unsupported key configuration format")
            return cls(
                salt=_unb64(d["salt"]),
                params=KdfParams(int(d["time_cost"]), int(d["memory_cost_kib"]), int(d["parallelism"])),
                key_version=int(d["key_version"]),
                canary_nonce=_unb64(d["canary_nonce"]),
                canary_ct=_unb64(d["canary_ct"]),
            )
        except KeyConfigError:
            raise
        except Exception as exc:  # malformed JSON, bad base64, missing keys
            raise KeyConfigError("key configuration file is malformed") from exc


def create_key_config(
    passphrase: str, params: KdfParams, path: Path, *, key_version: int = 1
) -> tuple[KeyConfig, DerivedKeys]:
    """Create a fresh key configuration file (mode 0600, never overwrites)."""
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise ValueError(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
    salt = secrets.token_bytes(32)
    keys = derive_keys(passphrase, salt, params)
    nonce, ct = aes_gcm_encrypt(keys.kek, _CANARY_PLAINTEXT, _CANARY_AAD)
    config = KeyConfig(salt, params, key_version, nonce, ct)

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)  # FileExistsError if present
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(config.to_json())
        fh.flush()
        os.fsync(fh.fileno())
    return config, keys


def load_key_config(path: Path) -> KeyConfig:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyConfigError(f"cannot read key configuration: {exc.strerror}") from exc
    return KeyConfig.from_json(text)


def unlock_keys(passphrase: str, config: KeyConfig) -> DerivedKeys:
    """Derive keys and verify them against the stored canary."""
    keys = derive_keys(passphrase, config.salt, config.params)
    try:
        plain = aes_gcm_decrypt(keys.kek, config.canary_nonce, config.canary_ct, _CANARY_AAD)
    except DecryptionError:
        raise InvalidPassphraseError("incorrect passphrase or tampered key configuration") from None
    if not hmac.compare_digest(plain, _CANARY_PLAINTEXT):
        raise InvalidPassphraseError("incorrect passphrase or tampered key configuration")
    return keys


# --------------------------------------------------------------------------
# KeyService: holds key material in memory only
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class WrappedKey:
    wrapped_dek: bytes
    wrap_nonce: bytes
    key_version: int


def _wrap_aad(evidence_id: uuid.UUID | str, key_version: int) -> bytes:
    return b"dems/v1/dek-wrap|" + str(evidence_id).encode("ascii") + b"|" + struct.pack(">I", key_version)


def _zero(buf: bytearray) -> None:
    buf[:] = bytes(len(buf))


class KeyService:
    """In-memory holder of the KEK and sub-keys. Never persisted, never logged."""

    def __init__(self) -> None:
        self._kek: bytearray | None = None
        self._audit: bytearray | None = None
        self._totp: bytearray | None = None
        self._backup: bytearray | None = None
        self._key_version = 0

    def __repr__(self) -> str:
        return f"KeyService(initialized={self.is_initialized})"

    # -- lifecycle --------------------------------------------------------
    @property
    def is_initialized(self) -> bool:
        return self._kek is not None

    @property
    def key_version(self) -> int:
        self._require()
        return self._key_version

    def initialize(self, passphrase: str, key_config_path: Path, params: KdfParams) -> None:
        """Unlock an existing key configuration, or create one on first run.

        For an existing configuration the stored KDF parameters are used, not
        ``params``, so changing settings can never silently change the KEK.
        """
        path = Path(key_config_path)
        if path.exists():
            config = load_key_config(path)
            keys = unlock_keys(passphrase, config)
        else:
            try:
                config, keys = create_key_config(passphrase, params, path)
            except FileExistsError:  # lost a startup race with another process
                config = load_key_config(path)
                keys = unlock_keys(passphrase, config)
        self.close()
        self._kek = bytearray(keys.kek)
        self._audit = bytearray(keys.audit_key)
        self._totp = bytearray(keys.totp_key)
        self._backup = bytearray(keys.backup_key)
        self._key_version = config.key_version

    def close(self) -> None:
        """Best-effort zeroisation of key buffers (Python cannot guarantee it)."""
        for buf in (self._kek, self._audit, self._totp, self._backup):
            if buf is not None:
                _zero(buf)
        self._kek = self._audit = self._totp = self._backup = None
        self._key_version = 0

    def _require(self) -> None:
        if self._kek is None:
            raise KeyServiceNotInitialized("key service is locked; start the server and enter the passphrase")

    # -- DEK wrapping -------------------------------------------------------
    def wrap_dek(self, dek: bytes, *, evidence_id: uuid.UUID | str) -> WrappedKey:
        self._require()
        _require_key(dek)
        assert self._kek is not None
        nonce, ct = aes_gcm_encrypt(bytes(self._kek), dek, _wrap_aad(evidence_id, self._key_version))
        return WrappedKey(wrapped_dek=ct, wrap_nonce=nonce, key_version=self._key_version)

    def unwrap_dek(
        self, wrapped_dek: bytes, wrap_nonce: bytes, *, evidence_id: uuid.UUID | str, key_version: int
    ) -> bytes:
        self._require()
        assert self._kek is not None
        if key_version != self._key_version:
            raise CryptoError(f"DEK was wrapped under KEK version {key_version}; rotation required")
        return aes_gcm_decrypt(bytes(self._kek), wrap_nonce, wrapped_dek, _wrap_aad(evidence_id, key_version))

    # -- Audit / custody HMAC -----------------------------------------------
    @property
    def hmac_key_version(self) -> int:
        return self.key_version

    def audit_hmac(self, entry_hash_hex: str) -> str:
        self._require()
        assert self._audit is not None
        return hmac_sha256_hex(bytes(self._audit), bytes.fromhex(entry_hash_hex))

    def verify_audit_hmac(self, entry_hash_hex: str, mac_hex: str) -> bool:
        return hmac.compare_digest(self.audit_hmac(entry_hash_hex), mac_hex.lower())

    # -- Sealing small secrets (e.g. TOTP seeds) --------------------------------
    def seal(self, plaintext: bytes, *, purpose: str) -> bytes:
        self._require()
        assert self._totp is not None
        nonce, ct = aes_gcm_encrypt(bytes(self._totp), plaintext, b"dems/v1/seal|" + purpose.encode())
        return nonce + ct

    def unseal(self, blob: bytes, *, purpose: str) -> bytes:
        self._require()
        assert self._totp is not None
        if len(blob) < NONCE_LEN + TAG_LEN:
            raise DecryptionError("sealed blob too short")
        return aes_gcm_decrypt(
            bytes(self._totp), blob[:NONCE_LEN], blob[NONCE_LEN:], b"dems/v1/seal|" + purpose.encode()
        )

    def backup_signing_key(self) -> bytes:
        self._require()
        assert self._backup is not None
        return bytes(self._backup)


key_service = KeyService()


def get_key_service() -> KeyService:
    """FastAPI-friendly accessor; raises if the service has not been unlocked."""
    if not key_service.is_initialized:
        raise KeyServiceNotInitialized("key service is locked")
    return key_service


def _resolve_passphrase(settings: Settings, *, confirm: bool) -> str:
    if settings.kek_passphrase is not None:
        return settings.kek_passphrase.get_secret_value()
    if not sys.stdin or not sys.stdin.isatty():
        raise KeyConfigError("KEK passphrase not configured and no terminal available to prompt for it")
    first = getpass.getpass("DEMS key passphrase: ")
    if confirm and getpass.getpass("Confirm new passphrase: ") != first:
        raise KeyConfigError("passphrases do not match")
    return first


def initialize_key_service(settings: Settings | None = None, *, passphrase: str | None = None) -> KeyService:
    """Unlock (or create) the key configuration at server startup."""
    settings = settings or get_settings()
    creating = not Path(settings.key_config_path).exists()
    secret = passphrase if passphrase is not None else _resolve_passphrase(settings, confirm=creating)
    key_service.initialize(secret, settings.key_config_path, KdfParams.from_settings(settings))
    return key_service


# --------------------------------------------------------------------------
# Streaming file encryption (AES-256-GCM, chunked)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class EncryptionResult:
    plaintext_sha256: str
    plaintext_size: int
    ciphertext_size: int
    chunk_size: int
    chunk_count: int


@dataclass(frozen=True)
class DecryptionResult:
    plaintext_sha256: str
    plaintext_size: int


def file_context(case_id: uuid.UUID | str, evidence_id: uuid.UUID | str) -> bytes:
    """Associated-data context binding ciphertext to one case and evidence item."""
    return f"dems/v1/file|{case_id}|{evidence_id}".encode("ascii")


def _read_exact(src: BinaryIO, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = src.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return parts[0] if len(parts) == 1 else b"".join(parts)


def _chunk_aad(header: bytes, index: int, final: bool, context: bytes) -> bytes:
    return header + struct.pack(">QB", index, 1 if final else 0) + context


def _unique_nonce(used: set[bytes]) -> bytes:
    while True:
        nonce = new_nonce()
        if nonce not in used:
            used.add(nonce)
            return nonce


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    dek: bytes,
    *,
    context: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: int | None = None,
) -> EncryptionResult:
    """Encrypt ``src`` into ``dst`` using the DEMS v1 chunked format.

    Layout: ``header(9) | { nonce(12) | ct_len(4) | ciphertext+tag }*``. Memory use
    is bounded by two chunks regardless of file size.
    """
    _require_key(dek)
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError("chunk_size out of range")

    header = struct.pack(_HEADER_FMT, FILE_MAGIC, FILE_FORMAT_VERSION, chunk_size)
    dst.write(header)
    aead = AESGCM(bytes(dek))
    sha = hashlib.sha256()
    used: set[bytes] = set()
    index = 0
    total = 0
    ct_total = len(header)

    current = _read_exact(src, chunk_size)
    while True:
        nxt = _read_exact(src, chunk_size) if len(current) == chunk_size else b""
        final = len(nxt) == 0

        total += len(current)
        if max_bytes is not None and total > max_bytes:
            raise SizeLimitExceeded("file exceeds the maximum allowed size")
        sha.update(current)

        nonce = _unique_nonce(used)
        ct = aead.encrypt(nonce, current, _chunk_aad(header, index, final, context))
        dst.write(nonce)
        dst.write(struct.pack(">I", len(ct)))
        dst.write(ct)
        ct_total += NONCE_LEN + 4 + len(ct)

        index += 1
        if final:
            break
        current = nxt

    return EncryptionResult(sha.hexdigest(), total, ct_total, chunk_size, index)


def iter_decrypt(src: BinaryIO, dek: bytes, *, context: bytes) -> Iterator[bytes]:
    """Yield verified plaintext chunks.

    Each chunk is authenticated before it is yielded. Truncation or reordering
    surfaces as :class:`DecryptionError` at the latest on the final chunk, so
    callers that must never emit unverified bytes should verify first with
    :func:`hash_decrypted`.
    """
    _require_key(dek)
    header = _read_exact(src, HEADER_LEN)
    if len(header) != HEADER_LEN:
        raise DecryptionError("truncated header")
    magic, version, chunk_size = struct.unpack(_HEADER_FMT, header)
    if magic != FILE_MAGIC or version != FILE_FORMAT_VERSION:
        raise DecryptionError("unrecognised file format")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise DecryptionError("invalid chunk size in header")

    aead = AESGCM(bytes(dek))
    record_head = NONCE_LEN + 4
    pending = b""
    index = 0
    while True:
        head = pending + _read_exact(src, record_head - len(pending))
        if len(head) != record_head:
            raise DecryptionError("truncated file")
        nonce = head[:NONCE_LEN]
        (ct_len,) = struct.unpack(">I", head[NONCE_LEN:])
        if ct_len < TAG_LEN or ct_len > chunk_size + TAG_LEN:
            raise DecryptionError("invalid chunk length")
        ct = _read_exact(src, ct_len)
        if len(ct) != ct_len:
            raise DecryptionError("truncated file")

        pending = _read_exact(src, 1)  # look-ahead: EOF means this must be the final chunk
        final = len(pending) == 0
        try:
            plain = aead.decrypt(nonce, ct, _chunk_aad(header, index, final, context))
        except InvalidTag:
            raise DecryptionError("chunk authentication failed (tampered, truncated or wrong key)") from None
        if (not final and len(plain) != chunk_size) or len(plain) > chunk_size:
            raise DecryptionError("unexpected chunk size")

        yield plain
        if final:
            return
        index += 1


def decrypt_stream(src: BinaryIO, dst: BinaryIO, dek: bytes, *, context: bytes) -> DecryptionResult:
    sha = hashlib.sha256()
    size = 0
    for chunk in iter_decrypt(src, dek, context=context):
        dst.write(chunk)
        sha.update(chunk)
        size += len(chunk)
    return DecryptionResult(sha.hexdigest(), size)


def hash_decrypted(src: BinaryIO, dek: bytes, *, context: bytes) -> DecryptionResult:
    """Decrypt in memory-bounded fashion, verifying every tag, and return the plaintext SHA-256."""
    sha = hashlib.sha256()
    size = 0
    for chunk in iter_decrypt(src, dek, context=context):
        sha.update(chunk)
        size += len(chunk)
    return DecryptionResult(sha.hexdigest(), size)


def _fsync_dir(directory: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def encrypt_file_atomic(
    src: BinaryIO,
    dest_path: Path,
    dek: bytes,
    *,
    context: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: int | None = None,
) -> EncryptionResult:
    """Encrypt to ``dest_path`` via a 0600 temp file, fsync, then atomic no-overwrite link."""
    dest_path = Path(dest_path)
    parent = dest_path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=".enc")  # created 0600
    try:
        with os.fdopen(fd, "wb") as dst:
            result = encrypt_stream(src, dst, dek, context=context, chunk_size=chunk_size, max_bytes=max_bytes)
            dst.flush()
            os.fsync(dst.fileno())
        os.link(tmp_name, dest_path)  # atomic; raises FileExistsError instead of overwriting evidence
        _fsync_dir(parent)
        return result
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


VerifyStatus = Literal["pass", "fail", "error"]


@dataclass(frozen=True)
class VerifyOutcome:
    status: VerifyStatus
    actual_sha256: str | None
    detail: str


def verify_encrypted_file(
    path: Path, dek: bytes, *, context: bytes, expected_sha256_hex: str
) -> VerifyOutcome:
    """Integrity verification: authenticated decrypt + SHA-256 compare (constant time)."""
    try:
        with open(path, "rb") as fh:
            result = hash_decrypted(fh, dek, context=context)
    except DecryptionError as exc:
        return VerifyOutcome("fail", None, f"ciphertext integrity failure: {exc}")
    except OSError as exc:
        return VerifyOutcome("error", None, f"cannot read file: {exc.strerror}")
    if constant_time_equals(result.plaintext_sha256, expected_sha256_hex.lower()):
        return VerifyOutcome("pass", result.plaintext_sha256, "hash matches recorded value")
    return VerifyOutcome("fail", result.plaintext_sha256, "hash differs from recorded value")


# Async wrappers: crypto and disk I/O are blocking, so run them off the event loop.
async def encrypt_file_atomic_async(*args: Any, **kwargs: Any) -> EncryptionResult:
    return await asyncio.to_thread(encrypt_file_atomic, *args, **kwargs)


async def verify_encrypted_file_async(*args: Any, **kwargs: Any) -> VerifyOutcome:
    return await asyncio.to_thread(verify_encrypted_file, *args, **kwargs)


# --------------------------------------------------------------------------
# Hash-chain helpers (custody events and audit log; Phase 1, section 2.5)
# --------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def details_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def format_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def genesis_hash(chain_id: uuid.UUID | str) -> str:
    return hashlib.sha256(b"DEMS-GENESIS" + str(chain_id).encode("utf-8")).hexdigest()


def compute_chain_hash(domain: bytes, fields: Sequence[str]) -> str:
    """SHA-256 over ``domain || (len32 || utf8(field))*`` - unambiguous field framing."""
    h = hashlib.sha256()
    h.update(domain)
    for value in fields:
        raw = value.encode("utf-8")
        h.update(struct.pack(">I", len(raw)))
        h.update(raw)
    return h.hexdigest()


def compute_custody_event_hash(
    *,
    chain_id: uuid.UUID | str,
    sequence_no: int,
    prev_event_hash: str,
    evidence_id: uuid.UUID | str | None,
    actor_id: uuid.UUID | str | None,
    actor_role: str,
    action: str,
    outcome: str,
    occurred_at: datetime,
    source_ip: str,
    details_hash_hex: str,
) -> str:
    return compute_chain_hash(
        CUSTODY_DOMAIN,
        [
            str(chain_id),
            str(sequence_no),
            prev_event_hash,
            "" if evidence_id is None else str(evidence_id),
            "" if actor_id is None else str(actor_id),
            actor_role,
            action,
            outcome,
            format_timestamp(occurred_at),
            source_ip,
            details_hash_hex,
        ],
    )


def compute_audit_entry_hash(
    *,
    sequence_no: int,
    prev_hash: str,
    occurred_at: datetime,
    actor_id: uuid.UUID | str | None,
    actor_username_attempted: str | None,
    action: str,
    resource_type: str | None,
    resource_id: uuid.UUID | str | None,
    outcome: str,
    source_ip: str,
    user_agent_hash: str,
    details_hash_hex: str,
) -> str:
    return compute_chain_hash(
        AUDIT_DOMAIN,
        [
            AUDIT_CHAIN_ID,
            str(sequence_no),
            prev_hash,
            format_timestamp(occurred_at),
            "" if actor_id is None else str(actor_id),
            actor_username_attempted or "",
            action,
            resource_type or "",
            "" if resource_id is None else str(resource_id),
            outcome,
            source_ip,
            user_agent_hash,
            details_hash_hex,
        ],
    )

