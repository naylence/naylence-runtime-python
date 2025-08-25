#!/usr/bin/env python3
"""
Integration test for routing with context preservation and loop prevention.

This test simulates a multi-hop routing scenario to verify that:
1. Context is properly preserved through routing decisions
2. Loop prevention works in realistic scenarios
3. Different routing paths behave correctly with context
"""

import asyncio
from typing import Optional
from unittest.mock import Mock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    NodeHeartbeatFrame,
    create_fame_envelope,
    format_address,
)
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Drop,
    ForwardChild,
    ForwardPeer,
    ForwardUp,
    RouterState,
    RoutingAction,
)


class MockRoutingNode:
    """Mock routing node that tracks routing decisions and context."""

    def __init__(self, node_id: str, physical_path: str = ""):
        self.node_id = node_id
        self.physical_path = physical_path
        self.policy = HybridPathRoutingPolicy()
        self.routing_calls = []
        self.delivered_messages = []

    def create_state(
        self,
        local: set = None,
        downstream_routes: dict = None,
        peer_routes: dict = None,
        has_parent: bool = True,
        physical_segments: list = None,
        child_segments: set = None,
        peer_segments: set = None,
    ) -> RouterState:
        """Create a RouterState for this node."""
        return RouterState(
            node_id=self.node_id,
            local=local or set(),
            downstream_address_routes=downstream_routes or {},
            peer_address_routes=peer_routes or {},
            pools={},
            has_parent=has_parent,
            physical_segments=physical_segments or [],
            child_segments=child_segments or set(),
            peer_segments=peer_segments or set(),
            resolve_address_by_capability=None,
            envelope_factory=Mock(),
        )

    async def route_message(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext],
        state: RouterState,
    ) -> RoutingAction:
        """Route a message and track the decision."""
        action = await self.policy.decide(envelope, state, context)

        self.routing_calls.append(
            {
                "envelope_id": envelope.id,
                "envelope_to": str(envelope.to) if envelope.to else None,
                "frame_type": envelope.frame.type,
                "context_origin": context.origin_type if context else None,
                "context_from": context.from_system_id if context else None,
                "action_type": type(action).__name__,
                "action_details": getattr(action, "segment", None)
                or getattr(action, "recipient_name", None),
            }
        )

        return action

    async def simulate_delivery(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Simulate local delivery."""
        self.delivered_messages.append(
            {
                "envelope_id": envelope.id,
                "envelope_to": str(envelope.to) if envelope.to else None,
                "context_origin": context.origin_type if context else None,
                "context_from": context.from_system_id if context else None,
            }
        )


@pytest.mark.asyncio
async def test_routing_integration_with_loop_prevention():
    """Test end-to-end routing with proper context and loop prevention."""
    print("🧪 Testing routing integration with loop prevention")

    # Create a three-tier routing scenario:
    # Root Node -> Middle Node -> Leaf Node
    root_node = MockRoutingNode("root", "/")
    middle_node = MockRoutingNode("middle", "/tier1")
    leaf_node = MockRoutingNode("leaf", "/tier1/tier2")

    # ═══════════════════════════════════════════════════════════════
    # Test 1: Normal downstream flow (LOCAL -> DOWNSTREAM -> DOWNSTREAM)
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 1: Normal downstream routing flow")

    target_addr = format_address("service", "/tier1/tier2/target")
    envelope = create_fame_envelope(frame=DataFrame(payload="downstream_test"), to=target_addr)

    # 1a) Root node: LOCAL origin, should forward to child
    root_state = root_node.create_state(physical_segments=[], child_segments={"tier1"}, has_parent=False)

    local_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="root")

    action = await root_node.route_message(envelope, local_context, root_state)
    assert isinstance(action, ForwardChild)
    assert action.segment == "tier1"
    print("✅ Root node correctly forwards LOCAL message to child")

    # 1b) Middle node: DOWNSTREAM origin, should forward to child
    middle_state = middle_node.create_state(
        physical_segments=["tier1"], child_segments={"tier2"}, has_parent=True
    )

    downstream_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,  # Would be set by root when forwarding
        from_system_id="root",
    )

    action = await middle_node.route_message(envelope, downstream_context, middle_state)
    assert isinstance(action, ForwardChild)
    assert action.segment == "tier2"
    print("✅ Middle node correctly forwards DOWNSTREAM message to child")

    # 1c) Leaf node: DOWNSTREAM origin, should deliver locally
    leaf_state = leaf_node.create_state(
        local={target_addr}, physical_segments=["tier1", "tier2"], has_parent=True
    )

    downstream_context_2 = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,  # Would be set by middle when forwarding
        from_system_id="middle",
    )

    action = await leaf_node.route_message(envelope, downstream_context_2, leaf_state)
    assert isinstance(action, DeliverLocal)
    assert action.recipient_name == target_addr
    print("✅ Leaf node correctly delivers DOWNSTREAM message locally")

    # ═══════════════════════════════════════════════════════════════
    # Test 2: Upstream loop prevention scenario
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 2: Upstream loop prevention")

    unknown_addr = format_address("unknown", "/unknown/service")
    upstream_envelope = create_fame_envelope(frame=DataFrame(payload="upstream_test"), to=unknown_addr)

    # 2a) Middle node receives message from upstream (would normally forward up)
    middle_fallback_state = middle_node.create_state(
        has_parent=True  # Has parent but should not forward due to upstream origin
    )

    upstream_context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, from_system_id="root")

    action = await middle_node.route_message(upstream_envelope, upstream_context, middle_fallback_state)
    assert isinstance(action, Drop)
    print("✅ Middle node correctly drops UPSTREAM message instead of forwarding upstream")

    # 2b) Same scenario but with DOWNSTREAM origin should forward upstream
    downstream_fallback_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="leaf"
    )

    action = await middle_node.route_message(
        upstream_envelope, downstream_fallback_context, middle_fallback_state
    )
    assert isinstance(action, ForwardUp)
    print("✅ Middle node correctly forwards DOWNSTREAM message upstream")

    # ═══════════════════════════════════════════════════════════════
    # Test 3: Control frame loop prevention
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 3: Control frame loop prevention")

    control_envelope = create_fame_envelope(frame=NodeHeartbeatFrame())

    # 3a) Control frame from upstream should be dropped
    action = await middle_node.route_message(control_envelope, upstream_context, middle_fallback_state)
    assert isinstance(action, Drop)
    print("✅ Middle node correctly drops UPSTREAM control frame")

    # 3b) Control frame from downstream should forward upstream
    action = await middle_node.route_message(
        control_envelope, downstream_fallback_context, middle_fallback_state
    )
    assert isinstance(action, ForwardUp)
    print("✅ Middle node correctly forwards DOWNSTREAM control frame upstream")

    # ═══════════════════════════════════════════════════════════════
    # Test 4: Peer routing with context
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 4: Peer routing preserves context behavior")

    peer_addr = format_address("peer-service", "/peer-target")
    peer_envelope = create_fame_envelope(frame=DataFrame(payload="peer_test"), to=peer_addr)

    # Middle node with peer routes
    peer_state = middle_node.create_state(
        peer_routes={peer_addr: "peer1"}, peer_segments={"peer1"}, has_parent=True
    )

    # 4a) UPSTREAM origin to peer should still route to peer (not loop prevention)
    action = await middle_node.route_message(peer_envelope, upstream_context, peer_state)
    assert isinstance(action, ForwardPeer)
    assert action.segment == "peer1"
    print("✅ Middle node correctly forwards UPSTREAM message to peer")

    # 4b) DOWNSTREAM origin to peer should also route to peer
    action = await middle_node.route_message(peer_envelope, downstream_fallback_context, peer_state)
    assert isinstance(action, ForwardPeer)
    assert action.segment == "peer1"
    print("✅ Middle node correctly forwards DOWNSTREAM message to peer")

    # ═══════════════════════════════════════════════════════════════
    # Test 5: No context fallback behavior
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 5: No context maintains backward compatibility")

    # Messages with no context should behave as before (forward upstream if possible)
    action = await middle_node.route_message(upstream_envelope, None, middle_fallback_state)
    assert isinstance(action, ForwardUp)
    print("✅ Middle node correctly forwards message with no context upstream")

    print("\n🎉 All routing integration tests passed!")

    # Print summary of routing decisions for debugging
    print("\n📊 Routing decisions summary:")
    all_nodes = [root_node, middle_node, leaf_node]
    for node in all_nodes:
        if node.routing_calls:
            print(f"\n{node.node_id} node decisions:")
            for call in node.routing_calls:
                print(
                    f"  📨 {call['frame_type']} -> {call['action_type']}"
                    f" (origin: {call['context_origin']}, from: {call['context_from']})"
                )


@pytest.mark.asyncio
async def test_context_preservation_edge_cases():
    """Test edge cases for context preservation in routing."""
    print("\n🧪 Testing context preservation edge cases")

    node = MockRoutingNode("test-node")
    policy = HybridPathRoutingPolicy()

    # ═══════════════════════════════════════════════════════════════
    # Test 1: PEER origin type behavior
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 1: PEER origin routing behavior")

    unknown_addr = format_address("unknown", "/peer-unknown")
    envelope = create_fame_envelope(frame=DataFrame(payload="peer_test"), to=unknown_addr)

    peer_context = FameDeliveryContext(origin_type=DeliveryOriginType.PEER, from_system_id="peer-node")

    state = node.create_state(has_parent=True)
    action = await policy.decide(envelope, state, peer_context)
    assert isinstance(action, ForwardUp)
    print("✅ PEER origin messages are forwarded upstream normally")

    # ═══════════════════════════════════════════════════════════════
    # Test 2: Mixed routing with different origins
    # ═══════════════════════════════════════════════════════════════
    print("\n📋 Test 2: Mixed routing scenarios")

    test_cases = [
        (DeliveryOriginType.LOCAL, True, "ForwardUp"),
        (DeliveryOriginType.DOWNSTREAM, True, "ForwardUp"),
        (DeliveryOriginType.PEER, True, "ForwardUp"),
        (DeliveryOriginType.UPSTREAM, False, "Drop"),
    ]

    for origin_type, should_forward, expected_action in test_cases:
        context = FameDeliveryContext(origin_type=origin_type, from_system_id=f"{origin_type.value}-node")

        action = await policy.decide(envelope, state, context)

        if should_forward:
            assert isinstance(action, ForwardUp), f"{origin_type} should forward upstream"
        else:
            assert isinstance(action, Drop), f"{origin_type} should be dropped"

        print(f"✅ {origin_type} origin -> {type(action).__name__} (expected {expected_action})")

    print("\n🎉 All edge case tests passed!")


if __name__ == "__main__":
    # Run the integration tests
    asyncio.run(test_routing_integration_with_loop_prevention())
    asyncio.run(test_context_preservation_edge_cases())
    print("\n✅ All routing integration tests completed successfully!")
