import asyncio
from typing import Any

import pytest
from pydantic import AnyUrl

from naylence.fame.core import FameEnvelope
from naylence.fame.mcp.default_mcp_host_service import (
    DefaultMCPHostService,
    _MCPSessionEntry,
)
from naylence.fame.mcp.mcp_host_service import APIKeyAuth

# Override DefaultMCPService.__init__ to disable background eviction task in tests
_instantiated_services = []
_orig_init = DefaultMCPHostService.__init__


@pytest.fixture(autouse=True, scope="module")
def swap_init():
    # run before first test in module
    _orig_init = DefaultMCPHostService.__init__
    DefaultMCPHostService.__init__ = _init_no_evict
    yield
    # run after last test in module
    DefaultMCPHostService.__init__ = _orig_init


def _init_no_evict(self, *args, **kwargs):
    # call original init but skip task creation
    self._sender = kwargs.get("sender")
    if not self._sender:
        if hasattr(kwargs, "sender") and kwargs["sender"]:
            self._sender = kwargs["sender"]
        else:
            from naylence.fame.node.node import get_node

            self._sender = get_node().deliver

    # Set up other attributes without creating the eviction task
    self._loop = kwargs.get("loop")
    if not self._loop:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, create a new one
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

    from collections import OrderedDict

    self._sessions = OrderedDict()
    self._default_server = None

    # Skip eviction task creation in tests
    self._evict_task = None

    # Set up other required attributes
    self._subscribers = {}
    self._subscribed_uris = set()
    self._closed = asyncio.Event()

    # Load env aliases (this should be safe)
    self._load_env_aliases()

    _instantiated_services.append(self)


class DummySession:
    def __init__(self):
        self.subscribed = []
        self.unsubscribed = []

    async def subscribe_resource(self, uri):
        self.subscribed.append(uri)

    async def unsubscribe_resource(self, uri):
        self.unsubscribed.append(uri)


class DummyFabric:
    def __init__(self):
        self.sent = []

    async def send(self, envelope):
        self.sent.append(envelope)


@pytest.fixture
def mcp_service(monkeypatch):
    async def dummy_send(envelope: FameEnvelope) -> None: ...

    service = DefaultMCPHostService(sender=dummy_send)

    # Register a dummy server
    async def dummy_handler(u: AnyUrl, notification: Any) -> None:
        # no-op
        return None

    entry = _MCPSessionEntry(
        endpoint="dummy",
        message_handler=dummy_handler,
        auth=APIKeyAuth("key"),
    )
    # Inject a dummy session
    dummy = DummySession()

    async def get_session() -> Any:
        return dummy

    entry.get = get_session
    service._sessions["alias"] = entry
    service._default_server = "alias"
    return service


@pytest.mark.asyncio
async def test_subscribe_once(mcp_service):
    svc = mcp_service
    url = "http://example.com/foo"
    await svc.subscribe_resource("sub@/", url)
    # Subscriber set updated
    key = AnyUrl(url)
    assert key in svc._subscribers
    subs = svc._subscribers[key]
    assert "sub@/" in subs
    # DummySession.subscribe_resource called once
    session = await svc._sessions["alias"].get()
    assert session.subscribed == [AnyUrl(url)]


@pytest.mark.asyncio
async def test_subscribe_idempotent(mcp_service):
    svc = mcp_service
    url = "http://example.com/foo"
    # Multiple subscribers
    await svc.subscribe_resource("sub1@/", url)
    await svc.subscribe_resource("sub2@/", url)
    key = AnyUrl(url)
    # Both in subscriber set
    assert svc._subscribers[key] == {"sub1@/", "sub2@/"}
    # DummySession.subscribe_resource still called only once
    session = await svc._sessions["alias"].get()
    assert session.subscribed == [AnyUrl(url)]


@pytest.mark.asyncio
async def test_unsubscribe_behavior(mcp_service):
    svc = mcp_service
    url = "http://example.com/foo"
    # Setup two subscribers
    await svc.subscribe_resource("sub1@/", url)
    await svc.subscribe_resource("sub2@/", url)
    key = AnyUrl(url)
    # Unsubscribe one
    await svc.unsubscribe_resource("sub1@/", url)
    assert svc._subscribers[key] == {"sub2@/"}
    # DummySession.unsubscribe_resource not called yet
    session = await svc._sessions["alias"].get()
    assert session.unsubscribed == []
    # Unsubscribe last
    await svc.unsubscribe_resource("sub2@/", url)
    assert key not in svc._subscribers
    # DummySession.unsubscribe_resource called once
    session = await svc._sessions["alias"].get()
    assert session.unsubscribed == [key]


@pytest.mark.asyncio
async def test_on_mcp_notification(monkeypatch, mcp_service):
    svc = mcp_service
    # Setup subscribers
    url = AnyUrl("http://example.com/resource")
    svc._subscribers[url] = {"subA@/", "subB@/"}
    # Fake fabric
    dummy_fabric = DummyFabric()
    svc._sender = dummy_fabric.send
    # Simulate notification
    notification = {"data": "update"}
    await svc._on_mcp_notification(url, notification)
    # Expect two envelopes sent
    assert len(dummy_fabric.sent) == 2
    tos = {env.to for env in dummy_fabric.sent}
    assert tos == {"subA@/", "subB@/"}
    # Check payloads
    for env in dummy_fabric.sent:
        assert env.frame.payload == {"uri": url, "update": notification}
