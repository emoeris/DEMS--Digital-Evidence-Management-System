"""Async engine, session factory and FastAPI dependency.

The engine is created lazily (first use) so tests can configure settings first.
Transactions are *not* committed automatically: services commit explicitly so
that an action and its audit/custody record land in one atomic transaction.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.db.models import Base


_IMMEDIATE_OPTION = "dems_sqlite_immediate"
_WRITE_TXN_KEY = "dems_write_txn"


def _configure_sqlite(engine: AsyncEngine) -> None:
    """Per-connection pragmas: FK enforcement, WAL, full durability, busy timeout."""

    @event.listens_for(engine.sync_engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None  # we emit BEGIN ourselves (see _begin below)
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=FULL")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()


    @event.listens_for(engine.sync_engine, "begin")
    def _begin(conn: Connection) -> None:
        mode = "IMMEDIATE" if conn.get_execution_options().get(_IMMEDIATE_OPTION) else "DEFERRED"
        conn.exec_driver_sql(f"BEGIN {mode}")


def create_engine_for_url(url: str, *, echo: bool = False) -> AsyncEngine:
    engine = create_async_engine(url, echo=echo, pool_pre_ping=not url.startswith("sqlite"))
    if engine.dialect.name == "sqlite":
        _configure_sqlite(engine)
    return engine


@lru_cache
def get_engine() -> AsyncEngine:
    s = get_settings()
    return create_engine_for_url(s.database_url, echo=s.debug)


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False, autoflush=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request; rolls back on error, always closes."""
    async with get_sessionmaker()() as session:
        try:
            yield session
        except BaseException:
            await session.rollback()
            raise


async def init_db(engine: AsyncEngine | None = None) -> None:
    """Create all tables (development / tests). Production schemas come from Alembic."""
    eng = engine or get_engine()
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def check_db(engine: AsyncEngine | None = None) -> bool:
    eng = engine or get_engine()
    async with eng.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True


async def dispose_engine() -> None:
    if get_engine.cache_info().currsize:
        await get_engine().dispose()
        get_engine.cache_clear()
        get_sessionmaker.cache_clear()


async def begin_write(session: AsyncSession) -> None:
    """Start (or confirm) a transaction that holds the database write lock.

    SQLite: ``BEGIN IMMEDIATE``, which serialises every writer. Because the
    audit and custody hash chains are read-then-append, this guarantees two
    requests can never read the same chain head. Any read-only transaction the
    request already opened (for example while authenticating) is ended first,
    so the lock is taken with a fresh snapshot.

    PostgreSQL: the transaction already exists; chain services additionally take
    row / advisory locks (``SELECT ... FOR UPDATE``, ``pg_advisory_xact_lock``).

    Idempotent within one transaction.
    """
    if session.get_bind().dialect.name != "sqlite":
        return
    sync = session.sync_session
    current = sync.get_transaction()
    if current is not None and sync.info.get(_WRITE_TXN_KEY) is current:
        return
    if current is not None:
        await session.commit()
    await session.connection(execution_options={_IMMEDIATE_OPTION: True})
    sync.info[_WRITE_TXN_KEY] = sync.get_transaction()
