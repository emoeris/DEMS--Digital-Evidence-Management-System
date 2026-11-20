import io
import os
import struct
import uuid
from datetime import datetime, timezone

import pytest

from app.core import crypto
from app.core.crypto import (
    MIN_CHUNK_SIZE, DecryptionError, InvalidPassphraseError, KeyService, KeyServiceNotInitialized,
    SizeLimitExceeded, derive_kek,
)
from tests.conftest import FAST_KDF

CS = MIN_CHUNK_SIZE
CTX = crypto.file_context(uuid.uuid4(), uuid.uuid4())


def enc(data: bytes, dek: bytes, ctx: bytes = CTX, chunk: int = CS) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(data), out, dek, context=ctx, chunk_size=chunk)
    return out.getvalue()


def dec(blob: bytes, dek: bytes, ctx: bytes = CTX) -> bytes:
    out = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(blob), out, dek, context=ctx)
    return out.getvalue()


def test_kek_is_32_bytes_deterministic_and_passphrase_bound():
    salt = os.urandom(32)
    a = derive_kek("passphrase-one-123", salt, FAST_KDF)
    assert len(a) == 32
    assert a == derive_kek("passphrase-one-123", salt, FAST_KDF)
    assert a != derive_kek("passphrase-two-123", salt, FAST_KDF)
    assert a != derive_kek("passphrase-one-123", os.urandom(32), FAST_KDF)


def test_subkeys_are_domain_separated():
    k = crypto.derive_keys("passphrase-one-123", os.urandom(32), FAST_KDF)
    assert len({k.kek, k.audit_key, k.totp_key, k.backup_key}) == 4
    assert "redacted" in repr(k)


def test_key_service_lifecycle(tmp_path):
    path = tmp_path / "kc.json"
    svc = KeyService()
    with pytest.raises(KeyServiceNotInitialized):
        svc.wrap_dek(crypto.generate_dek(), evidence_id=uuid.uuid4())
    svc.initialize("correct horse battery", path, FAST_KDF)
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    dek, eid = crypto.generate_dek(), uuid.uuid4()
    w = svc.wrap_dek(dek, evidence_id=eid)

    again = KeyService()
    again.initialize("correct horse battery", path, FAST_KDF)
    assert again.unwrap_dek(w.wrapped_dek, w.wrap_nonce, evidence_id=eid, key_version=w.key_version) == dek

    with pytest.raises(InvalidPassphraseError):
        KeyService().initialize("wrong passphrase here", path, FAST_KDF)

    svc.close()
    assert not svc.is_initialized
    assert "correct" not in repr(svc)


def test_wrapped_dek_bound_to_evidence_id(keys):
    dek = crypto.generate_dek()
    eid = uuid.uuid4()
    w = keys.wrap_dek(dek, evidence_id=eid)
    with pytest.raises(DecryptionError):
        keys.unwrap_dek(w.wrapped_dek, w.wrap_nonce, evidence_id=uuid.uuid4(), key_version=w.key_version)
    tampered = bytes([w.wrapped_dek[0] ^ 1]) + w.wrapped_dek[1:]
    with pytest.raises(DecryptionError):
        keys.unwrap_dek(tampered, w.wrap_nonce, evidence_id=eid, key_version=w.key_version)


def test_short_passphrase_rejected_on_create(tmp_path):
    with pytest.raises(ValueError):
        KeyService().initialize("short", tmp_path / "x.json", FAST_KDF)


@pytest.mark.parametrize("size", [0, 1, CS - 1, CS, CS + 1, 3 * CS, 3 * CS + 17])
def test_roundtrip_all_boundaries(size):
    dek = crypto.generate_dek()
    data = os.urandom(size)
    assert dec(enc(data, dek), dek) == data


def test_result_metadata_and_hash():
    dek = crypto.generate_dek()
    data = os.urandom(2 * CS + 5)
    out = io.BytesIO()
    r = crypto.encrypt_stream(io.BytesIO(data), out, dek, context=CTX, chunk_size=CS)
    import hashlib
    assert r.plaintext_sha256 == hashlib.sha256(data).hexdigest()
    assert r.plaintext_size == len(data) and r.chunk_count == 3
    assert r.ciphertext_size == len(out.getvalue())
    assert crypto.hash_decrypted(io.BytesIO(out.getvalue()), dek, context=CTX).plaintext_sha256 == r.plaintext_sha256


def test_nonces_unique_and_random():
    dek = crypto.generate_dek()
    blob = enc(os.urandom(20 * CS), dek)
    nonces, pos = [], crypto.HEADER_LEN
    while pos < len(blob):
        nonces.append(blob[pos:pos + 12])
        (n,) = struct.unpack(">I", blob[pos + 12:pos + 16])
        pos += 16 + n
    assert len(nonces) == 20 and len(set(nonces)) == 20


def test_same_plaintext_encrypts_differently():
    dek = crypto.generate_dek()
    data = os.urandom(1000)
    assert enc(data, dek) != enc(data, dek)


def test_tamper_detection():
    dek = crypto.generate_dek()
    blob = enc(os.urandom(3 * CS), dek)
    bad = bytearray(blob)
    bad[len(blob) // 2] ^= 0x01
    with pytest.raises(DecryptionError):
        dec(bytes(bad), dek)
    with pytest.raises(DecryptionError):
        dec(blob, crypto.generate_dek())                    # wrong key
    with pytest.raises(DecryptionError):
        dec(blob, dek, crypto.file_context(uuid.uuid4(), uuid.uuid4()))  # wrong context (swapped file)


def test_truncation_at_chunk_boundary_detected():
    dek = crypto.generate_dek()
    blob = enc(os.urandom(3 * CS), dek)
    record = 16 + CS + 16
    cut = blob[: crypto.HEADER_LEN + 2 * record]            # drop the final chunk cleanly
    with pytest.raises(DecryptionError):
        dec(cut, dek)
    with pytest.raises(DecryptionError):
        dec(blob[:-5], dek)                                  # mid-chunk truncation
    with pytest.raises(DecryptionError):
        dec(blob[:4], dek)


def test_chunk_reorder_detected():
    dek = crypto.generate_dek()
    blob = enc(os.urandom(3 * CS), dek)
    record = 16 + CS + 16
    h = crypto.HEADER_LEN
    c0, c1, c2 = (blob[h + i * record: h + (i + 1) * record] for i in range(3))
    with pytest.raises(DecryptionError):
        dec(blob[:h] + c1 + c0 + c2, dek)


def test_trailing_garbage_detected():
    dek = crypto.generate_dek()
    with pytest.raises(DecryptionError):
        dec(enc(os.urandom(100), dek) + b"\x00", dek)


def test_size_limit_enforced():
    with pytest.raises(SizeLimitExceeded):
        crypto.encrypt_stream(io.BytesIO(os.urandom(3 * CS)), io.BytesIO(), crypto.generate_dek(),
                              context=CTX, chunk_size=CS, max_bytes=2 * CS)


def test_atomic_file_write_permissions_and_no_overwrite(tmp_path):
    dek = crypto.generate_dek()
    data = os.urandom(CS + 3)
    dest = tmp_path / "vault" / "case" / "ev.enc"
    r = crypto.encrypt_file_atomic(io.BytesIO(data), dest, dek, context=CTX, chunk_size=CS)
    assert dest.exists() and [p.name for p in dest.parent.iterdir()] == ["ev.enc"]  # no temp left behind
    if os.name == "posix":
        assert oct(dest.stat().st_mode & 0o777) == "0o600"
        assert oct(dest.parent.stat().st_mode & 0o777) == "0o700"
    with pytest.raises(FileExistsError):
        crypto.encrypt_file_atomic(io.BytesIO(b"x"), dest, dek, context=CTX, chunk_size=CS)
    assert [p.name for p in dest.parent.iterdir()] == ["ev.enc"]

    ok = crypto.verify_encrypted_file(dest, dek, context=CTX, expected_sha256_hex=r.plaintext_sha256)
    assert ok.status == "pass"
    wrong = crypto.verify_encrypted_file(dest, dek, context=CTX, expected_sha256_hex="0" * 64)
    assert wrong.status == "fail"
    raw = bytearray(dest.read_bytes()); raw[40] ^= 1; dest.write_bytes(bytes(raw))
    assert crypto.verify_encrypted_file(dest, dek, context=CTX, expected_sha256_hex=r.plaintext_sha256).status == "fail"
    assert crypto.verify_encrypted_file(tmp_path / "missing", dek, context=CTX, expected_sha256_hex="0" * 64).status == "error"


async def test_async_wrappers(tmp_path):
    dek = crypto.generate_dek()
    dest = tmp_path / "a.enc"
    r = await crypto.encrypt_file_atomic_async(io.BytesIO(b"hello"), dest, dek, context=CTX, chunk_size=CS)
    out = await crypto.verify_encrypted_file_async(dest, dek, context=CTX, expected_sha256_hex=r.plaintext_sha256)
    assert out.status == "pass"


def test_hmac_and_audit_hmac(keys):
    h = "ab" * 32
    mac = keys.audit_hmac(h)
    assert keys.verify_audit_hmac(h, mac)
    assert not keys.verify_audit_hmac("cd" * 32, mac)
    assert not keys.verify_audit_hmac(h, "0" * 64)
    assert crypto.verify_hmac_hex(b"k" * 32, "data", crypto.hmac_sha256_hex(b"k" * 32, "data"))


def test_seal_roundtrip_and_purpose_binding(keys):
    blob = keys.seal(b"JBSWY3DPEHPK3PXP", purpose="totp-secret")
    assert keys.unseal(blob, purpose="totp-secret") == b"JBSWY3DPEHPK3PXP"
    with pytest.raises(DecryptionError):
        keys.unseal(blob, purpose="other")


def test_chain_hash_framing_and_determinism():
    d = crypto.CUSTODY_DOMAIN
    assert crypto.compute_chain_hash(d, ["ab", "c"]) != crypto.compute_chain_hash(d, ["a", "bc"])
    assert crypto.compute_chain_hash(d, ["x"]) == crypto.compute_chain_hash(d, ["x"])
    cid = uuid.uuid4()
    assert crypto.genesis_hash(cid) != crypto.genesis_hash(uuid.uuid4())
    ts = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc)
    assert crypto.format_timestamp(ts) == "2026-01-02T03:04:05.678901Z"
    kw = dict(chain_id=cid, sequence_no=1, prev_event_hash=crypto.genesis_hash(cid), evidence_id=None,
              actor_id=uuid.uuid4(), actor_role="investigator", action="INGEST", outcome="SUCCESS",
              occurred_at=ts, source_ip="127.0.0.1", details_hash_hex=crypto.details_hash({"a": 1}))
    h1 = crypto.compute_custody_event_hash(**kw)
    assert h1 == crypto.compute_custody_event_hash(**kw)
    assert h1 != crypto.compute_custody_event_hash(**{**kw, "action": "VIEW"})
    assert crypto.details_hash({"b": 1, "a": 2}) == crypto.details_hash({"a": 2, "b": 1})
    with pytest.raises(ValueError):
        crypto.format_timestamp(datetime(2026, 1, 1))
