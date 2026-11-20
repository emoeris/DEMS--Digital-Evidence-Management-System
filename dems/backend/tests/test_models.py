import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, update, delete
from sqlalchemy.exc import DatabaseError, IntegrityError, StatementError
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core import crypto
from app.db import models as m
from app.db.session import create_engine_for_url, init_db, check_db

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
async def db(tmp_path):
    engine = create_engine_for_url(f"sqlite+aiosqlite:///{tmp_path/'t.db'}")
    await init_db(engine)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def seed(s):
    admin = m.User(username="admin", email="a@x.io", password_hash="h", role=m.Role.ADMIN)
    s.add(admin); await s.flush()
    case = m.Case(case_number="C-1", title="t", created_by=admin.id)
    s.add(case); await s.flush()
    await s.commit()
    return admin, case


def event(case, admin, seq, prev):
    cid = case.id
    dh = crypto.details_hash({})
    eh = crypto.compute_custody_event_hash(chain_id=cid, sequence_no=seq, prev_event_hash=prev, evidence_id=None,
        actor_id=admin.id, actor_role="admin", action="CASE_CREATE", outcome="SUCCESS", occurred_at=NOW,
        source_ip="127.0.0.1", details_hash_hex=dh)
    return m.CustodyEvent(chain_id=cid, sequence_no=seq, actor_id=admin.id, actor_role="admin",
        action="CASE_CREATE", outcome=m.Outcome.SUCCESS, occurred_at=NOW, source_ip="127.0.0.1",
        details_json={}, details_hash=dh, prev_event_hash=prev, event_hash=eh, event_hmac="0" * 64, hmac_key_version=1)


async def test_db_health_and_schema(db):
    assert await check_db(db.bind)
    from sqlalchemy import inspect
    async with db.bind.connect() as conn:
        names = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    assert {"users", "cases", "evidence", "evidence_keys", "custody_events", "audit_log", "sessions",
            "refresh_tokens", "case_assignments", "revoked_access_tokens"} <= names


async def test_datetimes_roundtrip_as_aware_utc(db):
    admin, _ = await seed(db)
    got = (await db.execute(select(m.User))).scalar_one()
    assert got.created_at.tzinfo is not None and got.created_at.utcoffset().total_seconds() == 0
    with pytest.raises(StatementError, match="naive datetime rejected"):
        db.add(m.AuthSession(user_id=admin.id, expires_at=datetime(2026, 1, 1)))
        await db.flush()


async def test_foreign_keys_and_checks_enforced(db):
    admin, case = await seed(db)
    admin_id, case_id = admin.id, case.id   # rollback expires ORM attributes
    db.add(m.Evidence(case_id=uuid.uuid4(), original_filename="f", detected_mime="x/y", size_bytes=1,
        sha256_client="a" * 64, sha256_server="a" * 64, vault_path="p", chunk_size=1, ciphertext_size=1,
        uploaded_by=admin_id))
    with pytest.raises(IntegrityError):
        await db.flush()
    await db.rollback()
    db.add(m.Evidence(case_id=case_id, original_filename="f", detected_mime="x/y", size_bytes=1,
        sha256_client="a" * 64, sha256_server="b" * 64, vault_path="p2", chunk_size=1, ciphertext_size=1,
        uploaded_by=admin_id))
    with pytest.raises(IntegrityError):   # client and server hash must match
        await db.flush()
    await db.rollback()
    db.add(m.User(username="MixedCase", email="b@x.io", password_hash="h", role=m.Role.AUDITOR))
    with pytest.raises(IntegrityError):
        await db.flush()


async def test_evidence_with_wrapped_key_and_single_active_key(db):
    admin, case = await seed(db)
    ev = m.Evidence(case_id=case.id, original_filename="f", detected_mime="x/y", size_bytes=1,
        sha256_client="a" * 64, sha256_server="a" * 64, vault_path="c/e.enc", chunk_size=65536,
        ciphertext_size=50, uploaded_by=admin.id)
    db.add(ev); await db.flush()
    db.add(m.EvidenceKey(evidence_id=ev.id, key_version=1, wrapped_dek=b"w" * 48, wrap_nonce=b"n" * 12))
    await db.flush()
    db.add(m.EvidenceKey(evidence_id=ev.id, key_version=2, wrapped_dek=b"w" * 48, wrap_nonce=b"n" * 12))
    with pytest.raises(IntegrityError):    # second *active* key rejected
        await db.flush()


async def test_custody_chain_append_only_and_unique(db):
    admin, case = await seed(db)
    g = crypto.genesis_hash(case.id)
    e1 = event(case, admin, 1, g)
    db.add(e1); await db.commit()
    db.add(event(case, admin, 2, e1.event_hash)); await db.commit()

    db.add(event(case, admin, 2, e1.event_hash))        # fork attempt
    with pytest.raises(IntegrityError):
        await db.flush()
    await db.rollback()

    with pytest.raises(DatabaseError, match="append-only"):
        await db.execute(update(m.CustodyEvent).values(action="VIEW"))
    await db.rollback()
    with pytest.raises(DatabaseError, match="append-only"):
        await db.execute(delete(m.CustodyEvent))
    await db.rollback()
    assert len((await db.execute(select(m.CustodyEvent))).scalars().all()) == 2


async def test_audit_log_append_only(db):
    dh = crypto.details_hash({})
    prev = crypto.genesis_hash(crypto.AUDIT_CHAIN_ID)
    eh = crypto.compute_audit_entry_hash(sequence_no=1, prev_hash=prev, occurred_at=NOW, actor_id=None,
        actor_username_attempted="ghost", action="LOGIN_FAILURE", resource_type=None, resource_id=None,
        outcome="FAILURE", source_ip="127.0.0.1", user_agent_hash="u" * 64, details_hash_hex=dh)
    db.add(m.AuditLog(sequence_no=1, occurred_at=NOW, actor_username_attempted="ghost", action="LOGIN_FAILURE",
        outcome=m.Outcome.FAILURE, source_ip="127.0.0.1", user_agent_hash="u" * 64, details_json={},
        details_hash=dh, prev_hash=prev, entry_hash=eh, entry_hmac="0" * 64, hmac_key_version=1))
    await db.commit()
    with pytest.raises(DatabaseError, match="append-only"):
        await db.execute(update(m.AuditLog).values(action="LOGIN_SUCCESS"))


async def test_refresh_token_rotation_models(db):
    admin, _ = await seed(db)
    s = m.AuthSession(user_id=admin.id, expires_at=NOW)
    db.add(s); await db.flush()
    t1 = m.RefreshToken(session_id=s.id, jti="j1", token_hash="1" * 64, expires_at=NOW)
    db.add(t1); await db.flush()
    t2 = m.RefreshToken(session_id=s.id, jti="j2", token_hash="2" * 64, expires_at=NOW)
    db.add(t2); await db.flush()
    t1.status = m.RefreshTokenStatus.ROTATED; t1.replaced_by_id = t2.id
    await db.commit()
    db.add(m.RefreshToken(session_id=s.id, jti="j1", token_hash="3" * 64, expires_at=NOW))
    with pytest.raises(IntegrityError):    # jti unique
        await db.flush()


async def test_get_db_dependency(tmp_path, monkeypatch):
    from app.core.config import get_settings
    from app.db import session as sess
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path/'dep.db'}")
    get_settings.cache_clear(); sess.get_engine.cache_clear(); sess.get_sessionmaker.cache_clear()
    await sess.init_db()
    gen = sess.get_db()
    s = await gen.__anext__()
    assert (await s.execute(select(m.User))).first() is None
    await gen.aclose()
    await sess.dispose_engine()
    get_settings.cache_clear()
