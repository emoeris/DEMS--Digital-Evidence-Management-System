"""Custody chain: linkage, immutability, serialised concurrent appends, and tamper detection."""
import asyncio
import uuid

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DatabaseError

from app.core import crypto
from app.core.crypto import key_service
from app.db.models import AuditLog, CustodyAction, CustodyEvent, Outcome, Role, User
from app.db.session import get_engine, get_sessionmaker
from app.services import audit_service, evidence_service as es
from app.services.context import SYSTEM_CONTEXT
from tests.helpers import JPEG, PNG, make_actor, make_case, upload


async def build_chain(client, n: int = 5):
    """A real case with `n` events: one ingest, then verify/view events appended through the service."""
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    case = await make_case(client, inv)
    ev = (await upload(client, inv, case["id"], JPEG)).json()
    maker = get_sessionmaker()
    async with maker() as db:
        actor = await db.get(User, inv.id)
        for i in range(n - 1):
            await es.chain_append(db, case_id=uuid.UUID(case["id"]), actor=actor, action=CustodyAction.VIEW,
                                  outcome=Outcome.SUCCESS, ctx=SYSTEM_CONTEXT, evidence_id=uuid.UUID(ev["id"]),
                                  details={"n": i})
            await db.commit()
    return inv, uuid.UUID(case["id"]), uuid.UUID(ev["id"])


async def events(case_id):
    async with get_sessionmaker()() as db:
        rows = (await db.execute(select(CustodyEvent).where(CustodyEvent.chain_id == case_id)
                                 .order_by(CustodyEvent.sequence_no))).scalars().all()
        return list(rows)


async def verify(case_id):
    async with get_sessionmaker()() as db:
        return await es.verify_chain(db, case_id)


async def raw(sql: str, **params):
    """Simulates an attacker with direct database access (drops the append-only guards first)."""
    async with get_engine().begin() as conn:
        await conn.execute(text(sql), params)


async def disable_guards():
    for t in ("update", "delete"):
        await raw(f"DROP TRIGGER IF EXISTS trg_custody_events_no_{t}")
        await raw(f"DROP TRIGGER IF EXISTS trg_audit_log_no_{t}")


# ---------------------------------------------------------------- structure
async def test_chain_links_each_event_to_its_predecessor(client, env):
    _, case_id, _ = await build_chain(client, 5)
    rows = await events(case_id)
    assert [r.sequence_no for r in rows] == [1, 2, 3, 4, 5]
    assert rows[0].prev_event_hash == crypto.genesis_hash(case_id)              # genesis anchor
    for prev, cur in zip(rows, rows[1:]):
        assert cur.prev_event_hash == prev.event_hash                            # SHA-256 chaining
    assert len({r.event_hash for r in rows}) == 5
    for r in rows:
        assert len(r.event_hash) == 64 and r.hmac_key_version == key_service.key_version
        assert key_service.verify_audit_hmac(r.event_hash, r.event_hmac)
        assert r.event_hash == es._custody_hash_for(r)                          # recomputes from stored fields
    res = await verify(case_id)
    assert res.valid and res.events_checked == 5 and res.head_hash == rows[-1].event_hash
    assert res.broken_at_event_id is None and res.failure_type is None


async def test_genesis_differs_per_case(client, env):
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    a, b = await make_case(client, inv, "A-1"), await make_case(client, inv, "B-1")
    await upload(client, inv, a["id"], JPEG); await upload(client, inv, b["id"], PNG, "b.png", "image/png")
    ea, eb = await events(uuid.UUID(a["id"])), await events(uuid.UUID(b["id"]))
    assert ea[0].prev_event_hash != eb[0].prev_event_hash
    assert ea[0].event_hash != eb[0].event_hash


async def test_empty_chain_is_valid(client, env):
    inv = await make_actor(client, "inv1", Role.INVESTIGATOR)
    case = await make_case(client, inv)
    res = await verify(uuid.UUID(case["id"]))
    assert res.valid and res.events_checked == 0 and res.head_hash is None


# ---------------------------------------------------------------- immutability
async def test_database_refuses_update_and_delete_of_events(client, env):
    _, case_id, _ = await build_chain(client, 3)
    async with get_sessionmaker()() as db:
        with pytest.raises(DatabaseError, match="append-only"):
            await db.execute(update(CustodyEvent).where(CustodyEvent.chain_id == case_id).values(action="VIEW"))
        await db.rollback()
        with pytest.raises(DatabaseError, match="append-only"):
            await db.execute(text("DELETE FROM custody_events"))
        await db.rollback()
    assert (await verify(case_id)).valid


async def test_forking_the_chain_is_impossible_at_database_level(client, env):
    _, case_id, _ = await build_chain(client, 3)
    rows = await events(case_id)
    first = rows[0]
    async with get_sessionmaker()() as db:
        db.add(CustodyEvent(
            chain_id=case_id, sequence_no=2, actor_id=first.actor_id, actor_role="investigator", action="FORK",
            outcome=Outcome.SUCCESS, occurred_at=first.occurred_at, source_ip="127.0.0.1", details_json={},
            details_hash="0" * 64, prev_event_hash=first.event_hash, event_hash="f" * 64, event_hmac="0" * 64,
            hmac_key_version=1))
        with pytest.raises(Exception, match="UNIQUE"):
            await db.flush()


# ---------------------------------------------------------------- concurrency
async def test_concurrent_appends_produce_one_linear_chain(client, env):
    inv, case_id, _ = await build_chain(client, 1)
    maker = get_sessionmaker()

    async def append(i: int):
        async with maker() as db:
            actor = await db.get(User, inv.id)
            await es.chain_append(db, case_id=case_id, actor=actor, action=CustodyAction.VIEW,
                                  outcome=Outcome.SUCCESS, ctx=SYSTEM_CONTEXT, details={"i": i})
            await db.commit()

    await asyncio.gather(*(append(i) for i in range(30)))
    rows = await events(case_id)
    assert [r.sequence_no for r in rows] == list(range(1, 32))                  # no gaps, no duplicates
    assert all(b.prev_event_hash == a.event_hash for a, b in zip(rows, rows[1:]))
    assert (await verify(case_id)).valid


async def test_concurrent_api_requests_keep_both_chains_valid(client, env):
    inv, case_id, ev = await build_chain(client, 1)
    results = await asyncio.gather(*(client.get(f"/evidence/{ev}/metadata", headers=inv.headers) for _ in range(15)))
    assert all(r.status_code == 200 for r in results)
    assert (await verify(case_id)).valid
    async with get_sessionmaker()() as db:
        assert (await audit_service.verify_audit_chain(db)).valid


# ---------------------------------------------------------------- tamper / break detection
async def test_detects_modified_event_content(client, env):
    _, case_id, _ = await build_chain(client, 5)
    rows = await events(case_id)
    await disable_guards()
    await raw("UPDATE custody_events SET action = 'DOWNLOADED' WHERE id = :i", i=rows[2].id.hex)
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "CONTENT_TAMPERED"
    assert res.broken_at_event_id == rows[2].id and res.broken_at_sequence == 3 and res.events_checked == 2


async def test_detects_modified_details_json(client, env):
    _, case_id, _ = await build_chain(client, 4)
    rows = await events(case_id)
    await disable_guards()
    await raw("UPDATE custody_events SET details_json = :d WHERE id = :i", d='{"sha256": "forged"}', i=rows[0].id.hex)
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "CONTENT_TAMPERED" and res.broken_at_event_id == rows[0].id


async def test_detects_deleted_event_as_gap(client, env):
    _, case_id, _ = await build_chain(client, 5)
    rows = await events(case_id)
    await disable_guards()
    await raw("DELETE FROM custody_events WHERE id = :i", i=rows[2].id.hex)
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "GAP"
    assert res.broken_at_event_id == rows[3].id and res.broken_at_sequence == 4   # first event after the hole


async def test_detects_broken_link(client, env):
    _, case_id, _ = await build_chain(client, 5)
    rows = await events(case_id)
    await disable_guards()
    await raw("UPDATE custody_events SET prev_event_hash = :h WHERE id = :i", h="0" * 64, i=rows[3].id.hex)
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "LINK_BROKEN" and res.broken_at_event_id == rows[3].id


async def test_detects_bad_genesis(client, env):
    _, case_id, _ = await build_chain(client, 3)
    rows = await events(case_id)
    await disable_guards()
    await raw("UPDATE custody_events SET prev_event_hash = :h WHERE id = :i", h="1" * 64, i=rows[0].id.hex)
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "BAD_GENESIS" and res.broken_at_sequence == 1


async def test_detects_recomputed_hash_without_the_hmac_key(client, env):
    """An attacker who edits a row and recomputes its SHA-256 still cannot forge the HMAC."""
    _, case_id, _ = await build_chain(client, 5)
    rows = await events(case_id)
    victim = rows[2]
    forged = crypto.compute_custody_event_hash(
        chain_id=victim.chain_id, sequence_no=victim.sequence_no, prev_event_hash=victim.prev_event_hash,
        evidence_id=victim.evidence_id, actor_id=victim.actor_id, actor_role=victim.actor_role, action="DOWNLOADED",
        outcome=victim.outcome.value, occurred_at=victim.occurred_at, source_ip=victim.source_ip,
        details_hash_hex=victim.details_hash)
    await disable_guards()
    await raw("UPDATE custody_events SET action = 'DOWNLOADED', event_hash = :h WHERE id = :i", h=forged, i=victim.id.hex)
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "HMAC_INVALID" and res.broken_at_event_id == victim.id


async def test_detects_full_chain_rewrite_without_the_key(client, env):
    """Recomputing every hash after an edit still fails: HMACs need the secret audit key."""
    _, case_id, _ = await build_chain(client, 4)
    rows = await events(case_id)
    await disable_guards()
    prev = rows[0].prev_event_hash
    for r in rows:
        new_hash = crypto.compute_custody_event_hash(
            chain_id=r.chain_id, sequence_no=r.sequence_no, prev_event_hash=prev, evidence_id=r.evidence_id,
            actor_id=r.actor_id, actor_role=r.actor_role, action="TAMPERED" if r.sequence_no == 2 else r.action,
            outcome=r.outcome.value, occurred_at=r.occurred_at, source_ip=r.source_ip, details_hash_hex=r.details_hash)
        await raw("UPDATE custody_events SET prev_event_hash=:p, event_hash=:h, action=:a WHERE id=:i",
                  p=prev, h=new_hash, a="TAMPERED" if r.sequence_no == 2 else r.action, i=r.id.hex)
        prev = new_hash
    res = await verify(case_id)
    assert not res.valid and res.failure_type == "HMAC_INVALID" and res.broken_at_sequence == 2


async def test_intact_cases_are_unaffected_by_tampering_in_another_case(client, env):
    inv, case_a, _ = await build_chain(client, 3)
    case_b = uuid.UUID((await make_case(client, inv, "OTHER-1"))["id"])
    await upload(client, inv, str(case_b), PNG, "b.png", "image/png")
    rows = await events(case_a)
    await disable_guards()
    await raw("UPDATE custody_events SET action='X' WHERE id=:i", i=rows[1].id.hex)
    assert not (await verify(case_a)).valid and (await verify(case_b)).valid


async def test_verification_works_across_batch_boundaries(client, env, monkeypatch):
    from app.services import chain
    monkeypatch.setattr(chain, "BATCH_SIZE", 3)
    inv, case_id, _ = await build_chain(client, 8)
    async with get_sessionmaker()() as db:
        res = await chain.verify_chain_generic(
            db, CustodyEvent, where=[CustodyEvent.chain_id == case_id], prev_attr="prev_event_hash",
            hash_attr="event_hash", hmac_attr="event_hmac", recompute=es._custody_hash_for,
            genesis=crypto.genesis_hash(case_id), batch_size=3)
    assert res.valid and res.events_checked == 8
    rows = await events(case_id)
    await disable_guards()
    await raw("UPDATE custody_events SET action='X' WHERE id=:i", i=rows[6].id.hex)       # in the third batch
    async with get_sessionmaker()() as db:
        res = await chain.verify_chain_generic(
            db, CustodyEvent, where=[CustodyEvent.chain_id == case_id], prev_attr="prev_event_hash",
            hash_attr="event_hash", hmac_attr="event_hmac", recompute=es._custody_hash_for,
            genesis=crypto.genesis_hash(case_id), batch_size=3)
    assert not res.valid and res.broken_at_sequence == 7


# ---------------------------------------------------------------- API surface
async def test_verify_endpoint_reports_the_break_point(client, env):
    inv, case_id, _ = await build_chain(client, 4)
    ok = (await client.get(f"/custody/{case_id}/verify", headers=inv.headers)).json()
    assert ok["valid"] is True and ok["events_checked"] == 4 and ok["broken_at_event_id"] is None
    rows = await events(case_id)
    await disable_guards()
    await raw("UPDATE custody_events SET action='X' WHERE id=:i", i=rows[1].id.hex)
    bad = (await client.get(f"/custody/{case_id}/verify", headers=inv.headers)).json()
    assert bad["valid"] is False and bad["broken_at_event_id"] == str(rows[1].id)
    assert bad["failure_type"] == "CONTENT_TAMPERED" and bad["broken_at_sequence"] == 2


async def test_custody_endpoints_enforce_access(client, env):
    inv, case_id, _ = await build_chain(client, 2)
    other = await make_actor(client, "inv2", Role.INVESTIGATOR)
    auditor = await make_actor(client, "aud1", Role.AUDITOR)
    assert (await client.get(f"/custody/{case_id}", headers=other.headers)).status_code == 404
    assert (await client.get(f"/custody/{case_id}/verify", headers=other.headers)).status_code == 404
    assert (await client.get(f"/custody/{case_id}", headers=auditor.headers)).status_code == 200
    assert (await client.get(f"/custody/{case_id}/verify", headers=auditor.headers)).json()["valid"] is True
    assert (await client.get(f"/custody/{uuid.uuid4()}", headers=auditor.headers)).status_code == 404
    assert (await client.get(f"/custody/{case_id}")).status_code == 401


# ---------------------------------------------------------------- audit log chain
async def test_audit_chain_verifies_and_detects_tampering(client, env):
    inv, case_id, _ = await build_chain(client, 3)
    admin = await make_actor(client, "admin1", Role.ADMIN)
    ok = (await client.get("/audit/verify", headers=admin.headers)).json()
    assert ok["valid"] is True and ok["events_checked"] >= 4

    async with get_sessionmaker()() as db:
        rows = (await db.execute(select(AuditLog).order_by(AuditLog.sequence_no))).scalars().all()
    await disable_guards()
    await raw("UPDATE audit_log SET outcome = 'DENIED' WHERE id = :i", i=rows[3].id.hex)
    bad = (await client.get("/audit/verify", headers=admin.headers)).json()
    assert bad["valid"] is False and bad["failure_type"] == "CONTENT_TAMPERED" and bad["broken_at_sequence"] == 4
