from typing import Mapping

import pytest

from naylence.fame.core import (
    DataFrame,
    FameAddress,
    FameService,
    create_fame_envelope,
    format_address,
)
from naylence.fame.sentinel.capability_aware_routing_policy import (
    CapabilityAwareRoutingPolicy,
)
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Drop,
    ForwardChild,
    ForwardUp,
    RouterState,
)
from naylence.fame.service.service_manager import ServiceManager


# ——— Stub out the ServiceManager ———
class StubServiceManager(ServiceManager):
    def __init__(self, result=None, exc=None):
        self._res = result
        self._exc = exc

    async def resolve_address_by_capability(self, capabilities):
        if self._exc:
            raise self._exc
        return self._res

    def resolve_by_capability(self, capability: object) -> FameService:
        class DummyService(FameService):
            @property
            def capabilities(self):
                return []

        return DummyService()

    async def register_service(self, service_name: str, service: FameService) -> FameAddress:
        return FameAddress("dummy@/test")

    def get_local_services(self) -> Mapping[FameAddress, FameService]:
        return {}

    async def start(self):
        pass

    async def stop(self):
        pass


@pytest.mark.asyncio
async def test_to_address_not_routable(monkeypatch):
    """If envelope.to is set, we defer back to HybridPathRoutingPolicy."""
    # Use a fake secondary that always returns ForwardUp
    svc = StubServiceManager()
    policy = CapabilityAwareRoutingPolicy()

    addr = format_address("svc", "/foo")
    env = create_fame_envelope(frame=DataFrame(payload="x"), to=addr)
    state = RouterState(
        node_id="n",
        local=set(),
        downstream_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments=set(),
        resolve_address_by_capability=svc.resolve_address_by_capability,
        peer_segments=set(),
    )
    action = await policy.decide(env, state)
    assert isinstance(action, Drop)


@pytest.mark.asyncio
async def test_capability_local(monkeypatch):
    """Resolved capability that maps to a local address → DeliverLocal."""
    addr = format_address("svc", "/bar")
    svc = StubServiceManager(result=addr)
    policy = CapabilityAwareRoutingPolicy()

    env = create_fame_envelope(frame=DataFrame(payload="y"), to=None)
    env.capabilities = ["cap1"]
    state = RouterState(
        node_id="n",
        local={addr},
        downstream_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments=set(),
        resolve_address_by_capability=svc.resolve_address_by_capability,
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, DeliverLocal)
    assert action.recipient_name == addr


@pytest.mark.asyncio
async def test_capability_downstream(monkeypatch):
    """Resolved capability that maps to downstream → ForwardChild."""
    addr = format_address("svc", "/baz")
    svc = StubServiceManager(result=addr)
    policy = CapabilityAwareRoutingPolicy()

    env = create_fame_envelope(frame=DataFrame(payload="z"), to=None, capabilities=["cap2"])
    state = RouterState(
        node_id="n",
        local=set(),
        downstream_address_routes={addr: "segZ"},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments={"segZ"},
        capabilities={"cap2": {FameAddress("dummy@/"): "segZ"}},
        resolve_address_by_capability=svc.resolve_address_by_capability,
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, ForwardChild)
    assert action.segment == "segZ"


@pytest.mark.asyncio
async def test_capability_fallback_up_or_drop(monkeypatch):
    """Unresolved cap: bubble upstream if has_parent, else Drop."""
    svc = StubServiceManager(result=None)
    policy = CapabilityAwareRoutingPolicy()

    env = create_fame_envelope(frame=DataFrame(payload="?"), capabilities=["capX"])

    # when has_parent
    state_up = RouterState(
        node_id="n",
        local=set(),
        downstream_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        resolve_address_by_capability=svc.resolve_address_by_capability,
        peer_segments=set(),
    )
    action_up = await policy.decide(env, state_up)
    assert isinstance(action_up, ForwardUp)

    # when no parent
    state_drop = RouterState(
        node_id="n",
        local=set(),
        downstream_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments=set(),
        resolve_address_by_capability=svc.resolve_address_by_capability,
        peer_segments=set(),
    )
    action_drop = await policy.decide(env, state_drop)
    assert isinstance(action_drop, Drop)


@pytest.mark.asyncio
async def test_capability_error_then_drop(monkeypatch):
    """Exception in resolve_address_by_capability → Drop."""
    svc = StubServiceManager(exc=RuntimeError("boom"))
    policy = CapabilityAwareRoutingPolicy()

    env = create_fame_envelope(frame=DataFrame(payload="!"), to=None, capabilities=["capErr"])
    state = RouterState(
        node_id="n",
        local=set(),
        downstream_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments=set(),
        resolve_address_by_capability=svc.resolve_address_by_capability,
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, Drop)
