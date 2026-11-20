import os

# Settings must be in the environment before app modules are imported.
os.environ.update(
    {
        "SECRET_KEY": "test-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz",
        "KEK_PASSPHRASE": "test-passphrase-for-unit-tests",
        "ENVIRONMENT": "test",
        "KDF_MEMORY_KIB": "1024",
        "KDF_TIME_COST": "1",
        "KDF_PARALLELISM": "1",
        "PASSWORD_MEMORY_KIB": "1024",
        "PASSWORD_TIME_COST": "1",
        "PASSWORD_PARALLELISM": "1",
    }
)

import pytest  # noqa: E402

from app.core.crypto import KdfParams, KeyService, key_service  # noqa: E402

FAST_KDF = KdfParams(time_cost=1, memory_cost_kib=1024, parallelism=1)


@pytest.fixture
def keys(tmp_path) -> KeyService:
    svc = KeyService()
    svc.initialize("a-long-test-passphrase", tmp_path / "keyconfig.json", FAST_KDF)
    yield svc
    svc.close()


@pytest.fixture
def global_keys(tmp_path):
    key_service.initialize("a-long-test-passphrase", tmp_path / "kc.json", FAST_KDF)
    yield key_service
    key_service.close()


# ---------------------------------------------------------------------------
# Application-level fixtures (Phase 2B)
# ---------------------------------------------------------------------------
import httpx  # noqa: E402

from app.core.config import get_settings  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch, request):
    """Isolated settings: temp DB, vault and key file. Override with @pytest.mark.env(NAME=value)."""
    overrides = {
        "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'dems.db'}",
        "VAULT_PATH": str(tmp_path / "vault"),
        "KEY_CONFIG_PATH": str(tmp_path / "keyconfig.json"),
        "CHUNK_SIZE": str(64 * 1024),
        "MAX_LOGIN_ATTEMPTS": "3",
    }
    for marker in request.node.iter_markers("env"):
        overrides.update({k: str(v) for k, v in marker.kwargs.items()})
    for k, v in overrides.items():
        monkeypatch.setenv(k, v)
    from app.db import session as dbsession

    get_settings.cache_clear(); dbsession.get_engine.cache_clear(); dbsession.get_sessionmaker.cache_clear()
    yield get_settings()
    get_settings.cache_clear(); dbsession.get_engine.cache_clear(); dbsession.get_sessionmaker.cache_clear()


@pytest.fixture
async def app(env):
    from app.main import create_app

    application = create_app(env)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
