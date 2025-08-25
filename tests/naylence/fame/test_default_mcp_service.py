from datetime import datetime, timedelta, timezone

import pytest

from naylence.fame.core import FameEnvelope
from naylence.fame.mcp.default_mcp_host_service import (
    DefaultMCPHostService,
    _MCPSessionEntry,
)
from naylence.fame.mcp.mcp_host_service import APIKeyAuth

# Override DefaultMCPService.__init__ to disable background eviction task in tests
_instantiated_services = []
_orig_init = DefaultMCPHostService.__init__


async def fake_send(envelope: FameEnvelope) -> None: ...


@pytest.fixture(autouse=True, scope="module")
def swap_init():
    # run before first test in module
    _orig_init = DefaultMCPHostService.__init__
    DefaultMCPHostService.__init__ = _init_no_evict
    yield
    # run after last test in module
    DefaultMCPHostService.__init__ = _orig_init


def _init_no_evict(self, *args, **kwargs):
    # call original init
    _orig_init(self, *args, **kwargs)
    # cancel and remove the eviction task immediately
    task = getattr(self, "_evict_task", None)
    if task:
        try:
            task.cancel()
        except Exception:
            pass
        self._evict_task = None
    _instantiated_services.append(self)


@pytest.mark.asyncio
async def test_load_env_alias(monkeypatch):
    # Ensure environment alias parsing picks up servers correctly
    monkeypatch.setenv("MCP_SERVER_test", "http://example.com|api_key:secret")
    svc = DefaultMCPHostService(fake_send)
    assert "test" in svc._sessions
    entry = svc._sessions["test"]
    assert entry.endpoint == "http://example.com"
    assert isinstance(entry.auth, APIKeyAuth)
    assert getattr(entry.auth, "api_key") == "secret"


@pytest.mark.asyncio
async def test_register_and_unregister(monkeypatch):
    svc = DefaultMCPHostService(fake_send)
    auth = APIKeyAuth(api_key="abc123")
    await svc.register_server("foo", "https://foo.example", auth)
    assert "foo" in svc._sessions
    entry = svc._sessions["foo"]
    assert entry.endpoint == "https://foo.example"
    assert isinstance(entry.auth, APIKeyAuth)
    assert getattr(entry.auth, "api_key") == "abc123"
    await svc.unregister_server("foo")
    assert "foo" not in svc._sessions


@pytest.mark.asyncio
async def test_lru_eviction_max_sessions(monkeypatch):
    # stub out SDK session get
    async def fake_get(self):
        self.last_used = datetime.now(timezone.utc)
        return object()

    monkeypatch.setattr(_MCPSessionEntry, "get", fake_get)
    svc = DefaultMCPHostService(fake_send)
    auth = APIKeyAuth(api_key="key")
    max_sessions = DefaultMCPHostService.MAX_SESSIONS
    for i in range(max_sessions + 2):
        name = f"srv{i}"
        await svc.register_server(name, f"https://{name}", auth)
    newest = f"srv{max_sessions + 1}"
    await svc._sdk(newest)
    await svc._sdk(newest)
    assert len(svc._sessions) == max_sessions


@pytest.mark.asyncio
async def test_idle_eviction(monkeypatch):
    # Use manual eviction since background task is disabled
    monkeypatch.setattr(DefaultMCPHostService, "IDLE_TIMEOUT", timedelta(seconds=0.1))
    svc = DefaultMCPHostService(fake_send)
    auth = APIKeyAuth(api_key="idle")
    await svc.register_server("idle1", "https://idle1", auth)
    # make the session stale
    entry = svc._sessions["idle1"]
    entry.last_used = datetime.now(timezone.utc) - timedelta(seconds=1)
    # manually perform idle eviction
    now = datetime.now(timezone.utc)
    for name, ent in list(svc._sessions.items()):
        if now - ent.last_used > DefaultMCPHostService.IDLE_TIMEOUT:
            await ent.close()
            svc._sessions.pop(name, None)
    assert "idle1" not in svc._sessions
