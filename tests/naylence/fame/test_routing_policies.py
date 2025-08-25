import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    NodeHeartbeatFrame,
    create_fame_envelope,
    format_address,
)
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Drop,
    ForwardChild,
    ForwardUp,
    RouterState,
)


@pytest.mark.asyncio
async def test_deliver_local_when_address_in_local():
    policy = HybridPathRoutingPolicy()
    addr = format_address("svc", "/foo")
    env = create_fame_envelope(frame=DataFrame(payload="hello"), to=addr)

    state = RouterState(
        node_id="node1",
        local={addr},
        downstream_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, DeliverLocal)
    assert action.recipient_name == addr


@pytest.mark.asyncio
async def test_forward_child_when_address_in_downstream():
    policy = HybridPathRoutingPolicy()
    addr = format_address("svc", "/bar")
    env = create_fame_envelope(frame=DataFrame(payload="world"), to=addr)

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={addr: "child-seg"},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments={"child-seg"},
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, ForwardChild)
    assert action.segment == "child-seg"


@pytest.mark.asyncio
async def test_forward_up_when_no_match_but_has_parent():
    policy = HybridPathRoutingPolicy()
    addr = format_address("other", "/baz")
    env = create_fame_envelope(frame=DataFrame(payload="!"), to=addr)

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, ForwardUp)


@pytest.mark.asyncio
async def test_drop_when_no_match_and_no_parent():
    policy = HybridPathRoutingPolicy()
    addr = format_address("none", "/qux")
    env = create_fame_envelope(frame=DataFrame(payload="?"), to=addr)

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state)
    assert isinstance(action, Drop)


@pytest.mark.asyncio
async def test_physical_path_forward_child_and_deliver_local():
    policy = HybridPathRoutingPolicy()

    # ── deeper path → ForwardChild("child") ─────────────────────────
    addr_deep = format_address("svc", "/root/child/grand")
    env_deep = create_fame_envelope(frame=DataFrame(payload="x"), to=addr_deep)

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=False,
        physical_segments=["root"],
        child_segments={"child"},
        peer_segments=set(),
    )

    action_deep = await policy.decide(env_deep, state)
    assert isinstance(action_deep, ForwardChild)
    assert action_deep.segment == "child"

    # ── exact match → DeliverLocal ──────────────────────────────────
    addr_root = format_address("svc", "/root")
    env_root = create_fame_envelope(frame=DataFrame(payload="y"), to=addr_root)

    action_root = await policy.decide(env_root, state)
    assert isinstance(action_root, DeliverLocal)
    assert action_root.recipient_name == addr_root


# ════════════════════════════════════════════════════════════════════
# Loop Prevention Tests
# ════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_upstream_loop_prevention_fallback():
    """Test that messages from upstream are not forwarded back upstream in fallback case."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("unknown", "/unknown/path")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message came from upstream
    upstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node"
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,  # Has parent but should not forward upstream due to loop prevention
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state, upstream_context)
    assert isinstance(action, Drop), "Should drop messages from upstream instead of forwarding upstream"


@pytest.mark.asyncio
async def test_downstream_message_still_forwards_upstream():
    """Test that messages from downstream are still forwarded upstream normally."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("unknown", "/unknown/path")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message came from downstream
    downstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="downstream-node"
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state, downstream_context)
    assert isinstance(action, ForwardUp), "Should forward downstream messages upstream normally"


@pytest.mark.asyncio
async def test_no_context_still_forwards_upstream():
    """Test that messages with no context are still forwarded upstream normally."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("unknown", "/unknown/path")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state, None)
    assert isinstance(action, ForwardUp), "Should forward messages with no context upstream normally"


@pytest.mark.asyncio
async def test_control_frame_upstream_loop_prevention():
    """Test that control frames from upstream are not forwarded back upstream."""
    policy = HybridPathRoutingPolicy()
    env = create_fame_envelope(frame=NodeHeartbeatFrame())

    # Context indicating message came from upstream
    upstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node"
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state, upstream_context)
    assert isinstance(
        action, Drop
    ), "Should drop control frames from upstream instead of forwarding upstream"


@pytest.mark.asyncio
async def test_control_frame_downstream_still_forwards():
    """Test that control frames from downstream are still forwarded upstream."""
    policy = HybridPathRoutingPolicy()
    env = create_fame_envelope(frame=NodeHeartbeatFrame())

    # Context indicating message came from downstream
    downstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="downstream-node"
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state, downstream_context)
    assert isinstance(action, ForwardUp), "Should forward control frames from downstream upstream normally"


@pytest.mark.asyncio
async def test_local_origin_still_forwards_upstream():
    """Test that locally originated messages are still forwarded upstream."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("unknown", "/unknown/path")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message originated locally
    local_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="local-node")

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
    )

    action = await policy.decide(env, state, local_context)
    assert isinstance(action, ForwardUp), "Should forward locally originated messages upstream normally"


@pytest.mark.asyncio
async def test_downstream_loop_prevention_exact_logical_child():
    """Test that messages from downstream are not forwarded back to the same child."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("svc", "/bar")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message came from the same child we would forward to
    downstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="child1",  # Same as the route segment
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={addr: "child1"},  # Route maps to child1
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments={"child1"},
        peer_segments=set(),
    )

    action = await policy.decide(env, state, downstream_context)
    assert isinstance(action, Drop), "Should drop message to prevent downstream loop"


@pytest.mark.asyncio
async def test_downstream_loop_prevention_physical_routing():
    """Test that downstream loop prevention works in physical path routing."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("svc", "/child1/deep")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message came from child1
    downstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child1"
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],  # Root node
        child_segments={"child1"},
        peer_segments=set(),
    )

    action = await policy.decide(env, state, downstream_context)
    assert isinstance(action, Drop), "Should drop message to prevent downstream loop in physical routing"


@pytest.mark.asyncio
async def test_downstream_different_child_still_forwards():
    """Test that messages from downstream are forwarded to different children normally."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("svc", "/bar")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message came from a different child
    downstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="child2",  # Different from the route segment
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={addr: "child1"},  # Route maps to child1
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments={"child1", "child2"},
        peer_segments=set(),
    )

    action = await policy.decide(env, state, downstream_context)
    assert isinstance(action, ForwardChild), "Should forward to different child normally"
    assert action.segment == "child1"


@pytest.mark.asyncio
async def test_upstream_origin_still_forwards_to_children():
    """Test that messages from upstream are forwarded to children normally."""
    policy = HybridPathRoutingPolicy()
    addr = format_address("svc", "/bar")
    env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

    # Context indicating message came from upstream
    upstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.UPSTREAM, from_system_id="parent-node"
    )

    state = RouterState(
        node_id="node1",
        local=set(),
        downstream_address_routes={addr: "child1"},
        peer_address_routes={},
        pools={},
        has_parent=True,
        physical_segments=[],
        child_segments={"child1"},
        peer_segments=set(),
    )

    action = await policy.decide(env, state, upstream_context)
    assert isinstance(action, ForwardChild), "Should forward upstream messages to children normally"
    assert action.segment == "child1"
