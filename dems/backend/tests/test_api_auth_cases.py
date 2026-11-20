"""Authentication, lockout, token rotation, MFA, RBAC and case management through the HTTP API."""
import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from sqlalchemy import select, text

from app.core.security import create_access_token
from app.db.models import AuditLog, Role, User
from app.db.session import get_engine, get_sessionmaker
from tests.helpers import PASSWORD, create_user, login, make_actor, make_case


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def audit_actions(action: str | None = None):
    async with get_sessionmaker()() as db:
        q = select(AuditLog).order_by(AuditLog.sequence_no)
        rows = (await db.execute(q)).scalars().all()
        return [r.action for r in rows if action is None or r.action == action]


# ------------------------------------------------------------------ registration
async def test_register_is_admin_only_and_forces_password_change(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    payload = {"username": "NewUser", "email": "New@Example.org", "password": "Temp-Passw0rd!xyz", "role": "investigator"}
    assert (await client.post("/auth/register", json=payload)).status_code == 401
    assert (await client.post("/auth/register", json=payload, headers=inv.headers)).status_code == 403
    r = await client.post("/auth/register", json=payload, headers=admin.headers)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "newuser" and body["email"] == "new@example.org" and body["must_change_password"] is True
    assert payload["password"] not in r.text and "password_hash" not in r.text and "argon2" not in r.text
    assert (await client.post("/auth/register", json=payload, headers=admin.headers)).status_code == 409
    assert "USER_CREATE" in await audit_actions() and "AUTHZ_DENIED" in await audit_actions()


async def test_weak_passwords_rejected_without_echoing_them(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    for pw in ("short", "passwordpassword", "aaaaaaaaaaaaaaaa"):
        r = await client.post("/auth/register", headers=admin.headers,
                              json={"username": "weak1", "email": "w@example.org", "password": pw, "role": "auditor"})
        assert r.status_code == 422 and pw not in r.text
    r = await client.post("/auth/register", headers=admin.headers,
                          json={"username": "x", "email": "bad", "password": "P" * 200, "role": "root"})
    assert r.status_code == 422 and "P" * 20 not in r.text   # validation errors never echo submitted values


async def test_first_login_requires_password_change(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    await client.post("/auth/register", headers=admin.headers, json={
        "username": "fresh", "email": "f@example.org", "password": "Temp-Passw0rd!xyz", "role": "investigator"})
    r = await login(client, "fresh", "Temp-Passw0rd!xyz")
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    h = bearer(r.json()["access_token"])
    blocked = await client.get("/cases", headers=h)
    assert blocked.status_code == 403 and blocked.json()["code"] == "password_change_required"
    bad = await client.post("/auth/change-password", headers=h, json={"current_password": "wrong", "new_password": "N3w-Strong-Passphrase!"})
    assert bad.status_code == 401
    weak = await client.post("/auth/change-password", headers=h, json={"current_password": "Temp-Passw0rd!xyz", "new_password": "Temp-Passw0rd!xyz"})
    assert weak.status_code == 422                                   # reuse of the temporary password
    ok = await client.post("/auth/change-password", headers=h, json={"current_password": "Temp-Passw0rd!xyz", "new_password": "N3w-Strong-Passphrase!"})
    assert ok.status_code == 204
    assert (await client.get("/cases", headers=h)).status_code == 200
    assert (await login(client, "fresh", "Temp-Passw0rd!xyz")).status_code == 401
    assert (await login(client, "fresh", "N3w-Strong-Passphrase!")).json()["must_change_password"] is False


# ------------------------------------------------------------------ login and lockout
async def test_login_errors_are_uniform_for_unknown_user_and_wrong_password(client, env):
    await create_user("alice", Role.INVESTIGATOR)
    a = await login(client, "alice", "wrong-password-123")
    b = await login(client, "nobody", "wrong-password-123")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    assert "LOGIN_FAILURE" in await audit_actions()


async def test_account_lockout_after_threshold_then_expires(client, env):
    await create_user("alice", Role.INVESTIGATOR)
    for _ in range(3):                                                  # MAX_LOGIN_ATTEMPTS=3 in test settings
        assert (await login(client, "alice", "wrong-password-123")).status_code == 401
    locked = await login(client, "alice", PASSWORD)                     # correct password, but locked
    assert locked.status_code == 401 and "locked" in locked.json()["detail"].lower()
    assert "LOCKOUT" in await audit_actions()
    async with get_engine().begin() as conn:                            # lockout expires
        await conn.execute(text("UPDATE users SET locked_until = :t"), {"t": (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(tzinfo=None)})
    assert (await login(client, "alice", PASSWORD)).status_code == 200
    async with get_sessionmaker()() as db:
        user = (await db.execute(select(User).where(User.username == "alice"))).scalar_one()
        assert user.failed_login_count == 0 and user.locked_until is None


async def test_inactive_user_cannot_log_in(client, env):
    await create_user("gone", Role.AUDITOR)
    async with get_engine().begin() as conn:
        await conn.execute(text("UPDATE users SET is_active = 0"))
    assert (await login(client, "gone")).status_code == 401


# ------------------------------------------------------------------ tokens
async def test_refresh_rotation_and_reuse_detection(client, env):
    await create_user("alice", Role.INVESTIGATOR)
    t1 = (await login(client, "alice")).json()
    r2 = await client.post("/auth/refresh", json={"refresh_token": t1["refresh_token"]})
    assert r2.status_code == 200
    t2 = r2.json()
    assert t2["refresh_token"] != t1["refresh_token"]
    assert (await client.get("/auth/me", headers=bearer(t2["access_token"]))).status_code == 200

    replay = await client.post("/auth/refresh", json={"refresh_token": t1["refresh_token"]})   # stolen/used token
    assert replay.status_code == 401
    assert "TOKEN_REUSE_DETECTED" in await audit_actions()
    assert (await client.post("/auth/refresh", json={"refresh_token": t2["refresh_token"]})).status_code == 401   # family revoked
    assert (await client.get("/auth/me", headers=bearer(t2["access_token"]))).status_code == 401              # session dead too


async def test_token_type_confusion_and_garbage_rejected(client, env):
    await create_user("alice", Role.INVESTIGATOR)
    t = (await login(client, "alice")).json()
    assert (await client.get("/auth/me", headers=bearer(t["refresh_token"]))).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": t["access_token"]})).status_code == 401
    for bad in ("garbage", "a.b.c", t["access_token"][:-3] + "abc"):
        assert (await client.get("/auth/me", headers=bearer(bad))).status_code == 401
    assert (await client.get("/auth/me", headers={"Authorization": "Basic abc"})).status_code == 401


async def test_expired_access_token_rejected(client, env):
    user = await create_user("alice", Role.INVESTIGATOR)
    t = (await login(client, "alice")).json()
    sid = __import__("app.core.security", fromlist=["decode_token"]).decode_token(t["access_token"], expected_type="access").session_id
    old = create_access_token(user_id=user.id, role="investigator", session_id=sid, now=datetime.now(timezone.utc) - timedelta(hours=1))
    r = await client.get("/auth/me", headers=bearer(old.token))
    assert r.status_code == 401 and r.json()["code"] == "token_expired"


async def test_logout_revokes_access_and_refresh_tokens(client, env):
    await create_user("alice", Role.INVESTIGATOR)
    t = (await login(client, "alice")).json()
    assert (await client.post("/auth/logout", headers=bearer(t["access_token"]))).status_code == 204
    assert (await client.get("/auth/me", headers=bearer(t["access_token"]))).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": t["refresh_token"]})).status_code == 401
    assert "LOGOUT" in await audit_actions()


# ------------------------------------------------------------------ MFA
async def test_mfa_enrolment_login_replay_and_backup_codes(client, env):
    await create_user("alice", Role.INVESTIGATOR)
    t = (await login(client, "alice")).json()
    h = bearer(t["access_token"])
    assert (await client.post("/auth/mfa/verify", headers=h, json={"code": "123456"})).status_code == 409   # not enrolled yet

    enrol = (await client.post("/auth/mfa/enroll", headers=h)).json()
    assert enrol["provisioning_uri"].startswith("otpauth://totp/")
    async with get_sessionmaker()() as db:                               # the seed is stored encrypted
        stored = (await db.execute(select(User.mfa_secret_enc))).scalar_one()
        assert enrol["secret"].encode() not in stored
    totp = pyotp.TOTP(enrol["secret"])

    assert (await client.post("/auth/mfa/verify", headers=h, json={"code": "000000"})).status_code == 401
    v = await client.post("/auth/mfa/verify", headers=h, json={"code": totp.now()})
    assert v.status_code == 200 and len(v.json()["backup_codes"]) == 10
    backup = v.json()["backup_codes"]
    assert (await client.post("/auth/mfa/enroll", headers=h)).status_code == 409                 # already enabled

    needs = await login(client, "alice")
    assert needs.status_code == 401 and needs.json()["code"] == "mfa_required"
    assert (await login(client, "alice", totp_code=totp.now())).status_code == 401              # same step: replay rejected
    good = await login(client, "alice", totp_code=totp.at(time.time() + 30))
    assert good.status_code == 200 and good.json()["mfa_enabled"] is True
    assert (await client.get("/auth/me", headers=bearer(good.json()["access_token"]))).json()["session_mfa_verified"] is True

    assert (await login(client, "alice", backup_code=backup[0])).status_code == 200
    assert (await login(client, "alice", backup_code=backup[0])).status_code == 401              # single use
    assert (await login(client, "alice", backup_code="AAAAA-AAAAA")).status_code == 401


@pytest.mark.env(REQUIRE_ADMIN_MFA="true")
async def test_admin_must_complete_mfa_when_required(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    r = await client.get("/cases", headers=admin.headers)
    assert r.status_code == 403 and r.json()["code"] == "mfa_required"
    secret = (await client.post("/auth/mfa/enroll", headers=admin.headers)).json()["secret"]
    v = await client.post("/auth/mfa/verify", headers=admin.headers, json={"code": pyotp.TOTP(secret).now()})
    assert (await client.get("/cases", headers=bearer(v.json()["access_token"]))).status_code == 200


# ------------------------------------------------------------------ RBAC, cases, audit
async def test_case_role_matrix(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    inv2 = await make_actor(client, "inv2", Role.INVESTIGATOR)
    aud = await make_actor(client, "aud1", Role.AUDITOR)
    body = {"case_number": "C-100", "title": "Fraud inquiry"}

    assert (await client.post("/cases", json=body, headers=aud.headers)).status_code == 403    # auditors are read-only
    assert (await client.post("/cases", json=body)).status_code == 401
    mine = (await client.post("/cases", json=body, headers=inv.headers)).json()
    assert mine["lead_investigator_id"] == str(inv.id)
    assert (await client.post("/cases", json=body, headers=admin.headers)).status_code == 409   # duplicate number
    other = await client.post("/cases", headers=admin.headers, json={"case_number": "C-200", "title": "Other", "lead_investigator_id": str(inv2.id)})
    assert other.status_code == 201

    ids = lambda r: {c["id"] for c in r.json()["items"]}
    assert ids(await client.get("/cases", headers=inv.headers)) == {mine["id"]}                # sees only its own
    assert len(ids(await client.get("/cases", headers=admin.headers))) == 2
    assert len(ids(await client.get("/cases", headers=aud.headers))) == 2
    assert (await client.get(f"/cases/{other.json()['id']}", headers=inv.headers)).status_code == 404

    cid = mine["id"]
    assert (await client.patch(f"/cases/{cid}", json={"title": "Hacked"}, headers=aud.headers)).status_code == 403
    assert (await client.patch(f"/cases/{cid}", json={"title": "Fraud inquiry v2"}, headers=inv.headers)).json()["title"] == "Fraud inquiry v2"
    assert (await client.patch(f"/cases/{cid}", json={"lead_investigator_id": str(inv2.id)}, headers=inv.headers)).status_code == 403

    # assignments: lead/admin manage; a new member can then see the case
    assert (await client.post(f"/cases/{cid}/assignments", json={"user_id": str(inv2.id)}, headers=aud.headers)).status_code == 403
    assert (await client.post(f"/cases/{cid}/assignments", json={"user_id": str(aud.id)}, headers=inv.headers)).status_code == 422  # not an investigator
    assert (await client.post(f"/cases/{cid}/assignments", json={"user_id": str(inv2.id)}, headers=inv.headers)).status_code == 201
    assert (await client.post(f"/cases/{cid}/assignments", json={"user_id": str(inv2.id)}, headers=inv.headers)).status_code == 409
    assert (await client.get(f"/cases/{cid}", headers=inv2.headers)).status_code == 200
    assert (await client.post(f"/cases/{cid}/assignments", json={"user_id": str(inv.id)}, headers=inv2.headers)).status_code == 403  # not lead
    assert (await client.delete(f"/cases/{cid}/assignments/{inv.id}", headers=inv.headers)).status_code == 409                       # lead stays
    assert (await client.delete(f"/cases/{cid}/assignments/{inv2.id}", headers=inv.headers)).status_code == 204
    assert (await client.get(f"/cases/{cid}", headers=inv2.headers)).status_code == 404

    # closing locks the case and records a manifest on the custody chain
    closed = await client.post(f"/cases/{cid}/close", headers=inv.headers)
    assert closed.status_code == 200 and closed.json()["status"] == "closed" and len(closed.json()["closure_manifest_hash"]) == 64
    assert (await client.post(f"/cases/{cid}/close", headers=inv.headers)).status_code == 409
    assert (await client.patch(f"/cases/{cid}", json={"title": "late edit"}, headers=inv.headers)).status_code == 409
    assert (await client.post(f"/cases/{cid}/assignments", json={"user_id": str(inv2.id)}, headers=inv.headers)).status_code == 409
    chain = (await client.get(f"/custody/{cid}", headers=aud.headers)).json()["items"]
    assert chain[-1]["action"] == "CASE_CLOSE" and chain[-1]["details_json"]["closure_manifest_hash"] == closed.json()["closure_manifest_hash"]


async def test_case_deletion_rules(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    empty = await make_case(client, inv, "EMPTY-1")
    closed = await make_case(client, inv, "CLOSED-1")
    await client.post(f"/cases/{closed['id']}/close", headers=inv.headers)
    assert (await client.delete(f"/cases/{empty['id']}", headers=inv.headers)).status_code == 403   # admin only
    assert (await client.delete(f"/cases/{empty['id']}", headers=admin.headers)).status_code == 204
    assert (await client.get(f"/cases/{empty['id']}", headers=admin.headers)).status_code == 404
    r = await client.delete(f"/cases/{closed['id']}", headers=admin.headers)                       # has custody history
    assert r.status_code == 409 and r.json()["code"] == "case_has_records"
    assert "CASE_DELETE" in await audit_actions()


async def test_audit_endpoint_is_restricted_and_filterable(client, env):
    admin = await make_actor(client, "admin1", Role.ADMIN)
    aud = await make_actor(client, "aud1", Role.AUDITOR)
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    await make_case(client, inv)
    await client.post("/cases", json={"case_number": "X-1", "title": "denied"}, headers=aud.headers)   # generates AUTHZ_DENIED

    assert (await client.get("/audit", headers=inv.headers)).status_code == 403
    assert (await client.get("/audit")).status_code == 401
    r = await client.get("/audit", headers=aud.headers, params={"action": "AUTHZ_DENIED"})
    assert r.status_code == 200 and r.json()["total"] >= 2 and all(e["action"] == "AUTHZ_DENIED" for e in r.json()["items"])
    assert all("entry_hmac" not in e for e in r.json()["items"])                                       # internals not exposed
    created = (await client.get("/audit", headers=admin.headers, params={"action": "CASE_CREATE", "limit": 5})).json()
    assert created["total"] == 1 and created["items"][0]["resource_type"] == "case"
    assert (await client.get("/audit", headers=admin.headers, params={"limit": 1000})).status_code == 422
    assert "AUDIT_READ" in await audit_actions()


# ------------------------------------------------------------------ platform hardening
async def test_security_headers_cors_and_error_shape(client, env):
    r = await client.get("/health")
    assert r.status_code == 200 and r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store" and r.headers["x-request-id"]
    ok = await client.options("/cases", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
                                                 "Access-Control-Request-Headers": "authorization"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173"
    evil = await client.options("/cases", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in evil.headers
    assert (await client.get("/cases/not-a-uuid", headers={"Authorization": "Bearer x"})).status_code == 401


async def test_upload_guard_rejects_anonymous_and_oversized_requests(client, env):
    assert (await client.post("/evidence/upload", content=b"x")).status_code == 401
    r = await client.post("/evidence/upload", headers={"Authorization": "Bearer x", "Content-Length": str(10**12)}, content=b"x")
    assert r.status_code in (413, 400)


def test_settings_validation(monkeypatch):
    from pydantic import ValidationError
    from app.core.config import Settings
    base = dict(secret_key="s" * 40)
    with pytest.raises(ValidationError):
        Settings(secret_key="short")
    with pytest.raises(ValidationError):
        Settings(secret_key="change-me-" + "x" * 40)
    with pytest.raises(ValidationError):
        Settings(**base, cors_origins="*")
    with pytest.raises(ValidationError):
        Settings(**base, database_url="sqlite:///x.db")                       # no async driver
    with pytest.raises(ValidationError):
        Settings(**base, environment="production", cors_origins="http://localhost:5173")
    with pytest.raises(ValidationError):
        Settings(**base, environment="production", cors_origins="https://a.example", require_admin_mfa=False)
