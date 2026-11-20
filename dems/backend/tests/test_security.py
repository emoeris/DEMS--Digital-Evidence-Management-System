import time
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.core import security as sec


def test_password_hash_argon2id_and_verify():
    h = sec.hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert sec.verify_password("correct horse battery staple", h)
    assert not sec.verify_password("wrong", h)
    assert not sec.verify_password("x" * 500, h)
    assert not sec.verify_password("pw", "not-a-hash")
    assert sec.hash_password("same") != sec.hash_password("same")  # unique salts


def test_authenticate_unknown_user_is_false_without_error():
    assert sec.authenticate_password("whatever", None) == (False, False)
    h = sec.hash_password("a-long-password-123")
    assert sec.authenticate_password("a-long-password-123", h) == (True, False)


def test_password_policy():
    ok = sec.validate_password_policy("Tr1cky-unique-phrase!", username="alice")
    assert ok.valid
    assert not sec.validate_password_policy("short").valid
    assert not sec.validate_password_policy("PasswordPassword").valid
    assert not sec.validate_password_policy("aaaaaaaaaaaaaa").valid
    assert not sec.validate_password_policy("xx-alice-is-here-xx", username="alice").valid
    assert not sec.validate_password_policy("x" * 200).valid
    old = sec.hash_password("Tr1cky-unique-phrase!")
    assert not sec.validate_password_policy("Tr1cky-unique-phrase!", history_hashes=[old]).valid


def test_access_token_roundtrip():
    uid, sid = uuid.uuid4(), uuid.uuid4()
    t = sec.create_access_token(user_id=uid, role="auditor", session_id=sid, mfa_verified=True)
    c = sec.decode_token(t.token, expected_type="access")
    assert (c.subject, c.role, c.session_id, c.jti, c.mfa_verified) == (str(uid), "auditor", str(sid), t.jti, True)
    assert 890 <= (c.expires_at - c.issued_at).total_seconds() <= 910


def test_refresh_token_roundtrip_and_ttl():
    t = sec.create_refresh_token(user_id=uuid.uuid4(), session_id=uuid.uuid4())
    c = sec.decode_token(t.token, expected_type="refresh")
    assert c.role is None and (c.expires_at - c.issued_at) == timedelta(seconds=604800)
    assert len(sec.hash_token(t.token)) == 64


def test_token_type_confusion_rejected():
    a = sec.create_access_token(user_id=uuid.uuid4(), role="admin", session_id=uuid.uuid4())
    r = sec.create_refresh_token(user_id=uuid.uuid4(), session_id=uuid.uuid4())
    with pytest.raises(sec.TokenError):
        sec.decode_token(a.token, expected_type="refresh")
    with pytest.raises(sec.TokenError):
        sec.decode_token(r.token, expected_type="access")


def test_expired_tampered_and_garbage_tokens():
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    t = sec.create_access_token(user_id=uuid.uuid4(), role="admin", session_id=uuid.uuid4(), now=old)
    with pytest.raises(sec.TokenExpiredError):
        sec.decode_token(t.token, expected_type="access")
    good = sec.create_access_token(user_id=uuid.uuid4(), role="admin", session_id=uuid.uuid4()).token
    head, body, sig = good.split(".")
    for bad in (f"{head}.{body}.{sig[:-2]}AA", f"{head}.{body[:-2]}AA.{sig}", "a.b.c", "", "x" * 5000):
        with pytest.raises(sec.TokenError):
            sec.decode_token(bad, expected_type="access")


def test_alg_none_rejected():
    import base64, json
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    now = int(time.time())
    forged = b({"alg": "none", "typ": "JWT"}) + "." + b(
        {"sub": "x", "type": "access", "sid": "s", "jti": "j", "iss": "dems", "aud": "dems-api",
         "iat": now, "nbf": now, "exp": now + 900, "role": "admin"}) + "."
    with pytest.raises(sec.TokenError):
        sec.decode_token(forged, expected_type="access")


def test_totp_verify_replay_and_drift():
    secret = sec.generate_totp_secret()
    totp = pyotp.TOTP(secret)
    now = time.time()
    code = totp.at(now)
    counter = sec.verify_totp(secret, code, now=now)
    assert counter == sec.current_totp_counter(now)
    assert sec.verify_totp(secret, code, last_used_counter=counter, now=now) is None  # replay
    assert sec.verify_totp(secret, totp.at(now - 30), now=now) is not None            # drift -1
    assert sec.verify_totp(secret, totp.at(now - 120), now=now) is None
    assert sec.verify_totp(secret, "12345", now=now) is None
    assert sec.verify_totp(secret, "abcdef", now=now) is None
    assert sec.verify_totp(secret, " " + code[:3] + " " + code[3:], now=now) == counter  # spaces tolerated
    assert "otpauth://totp/" in sec.totp_provisioning_uri(secret, "alice@example.com")


def test_totp_secret_encrypted_at_rest(global_keys):
    secret = sec.generate_totp_secret()
    blob = sec.encrypt_totp_secret(secret)
    assert secret.encode() not in blob
    assert sec.decrypt_totp_secret(blob) == secret


def test_backup_codes_single_use_flow():
    shown, hashes = sec.generate_backup_codes(3)
    assert len(shown) == 3 and all(len(c) == 11 and c[5] == "-" for c in shown)
    assert sec.verify_backup_code(shown[1].lower(), hashes) == 1
    assert sec.verify_backup_code("AAAAA-AAAAA", hashes) is None
    assert sec.verify_backup_code("short", hashes) is None
