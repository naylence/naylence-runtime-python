#!/usr/bin/env python3
"""
Test script to verify the upstream loop prevention in HybridPathRoutingPolicy.
"""

import asyncio
from unittest.mock import Mock

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    create_fame_envelope,
)
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.router import Drop, ForwardUp, RouterState


def create_test_router_state(has_parent=True):
    """Create a test RouterState for testing."""
    return RouterState(
        node_id="test-node",
        local=set(),
        downstream_address_routes={},
        peer_address_routes={},
        pools={},
        has_parent=has_parent,
        physical_segments=[],
        child_segments=set(),
        peer_segments=set(),
        resolve_address_by_capability=None,
        envelope_factory=Mock(),
    )


async def test_upstream_loop_prevention():
    """Test that messages from upstream are not forwarded back upstream."""
    print("🧪 Testing upstream loop prevention in HybridPathRoutingPolicy")

    policy = HybridPathRoutingPolicy()

    # Test case 1: Message with UPSTREAM origin should not be forwarded upstream
    print("\n📋 Test 1: UPSTREAM origin message should not forward upstream")

    envelope = create_fame_envelope(
        frame=DataFrame(payload="test"), to=FameAddress("unknown@/unknown/path")
    )

    context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node")

    state = create_test_router_state(has_parent=True)

    action = await policy.decide(envelope, state, context)

    assert isinstance(action, Drop), f"Expected Drop, got {type(action).__name__}"
    print("✅ UPSTREAM origin message correctly dropped instead of forwarded upstream")

    # Test case 2: Message with DOWNSTREAM origin should be forwarded upstream (normal case)
    print("\n📋 Test 2: DOWNSTREAM origin message should forward upstream normally")

    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="downstream-node"
    )

    action = await policy.decide(envelope, state, context)

    assert isinstance(action, ForwardUp), f"Expected ForwardUp, got {type(action).__name__}"
    print("✅ DOWNSTREAM origin message correctly forwarded upstream")

    # Test case 3: Message with LOCAL origin should be forwarded upstream
    print("\n📋 Test 3: LOCAL origin message should forward upstream normally")

    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="local-node")

    action = await policy.decide(envelope, state, context)

    assert isinstance(action, ForwardUp), f"Expected ForwardUp, got {type(action).__name__}"
    print("✅ LOCAL origin message correctly forwarded upstream")

    # Test case 4: Message with no context should be forwarded upstream
    print("\n📋 Test 4: Message with no context should forward upstream normally")

    action = await policy.decide(envelope, state, None)

    assert isinstance(action, ForwardUp), f"Expected ForwardUp, got {type(action).__name__}"
    print("✅ Message with no context correctly forwarded upstream")

    # Test case 5: Control frame with UPSTREAM origin should not be forwarded upstream
    print("\n📋 Test 5: Control frame from UPSTREAM origin should not forward upstream")

    from naylence.fame.core import NodeHeartbeatFrame

    control_envelope = create_fame_envelope(frame=NodeHeartbeatFrame())

    context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node")

    action = await policy.decide(control_envelope, state, context)

    assert isinstance(action, Drop), f"Expected Drop, got {type(action).__name__}"
    print("✅ Control frame from UPSTREAM origin correctly dropped")

    # Test case 6: Control frame with DOWNSTREAM origin should be forwarded upstream
    print("\n📋 Test 6: Control frame from DOWNSTREAM origin should forward upstream")

    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="downstream-node"
    )

    action = await policy.decide(control_envelope, state, context)

    assert isinstance(action, ForwardUp), f"Expected ForwardUp, got {type(action).__name__}"
    print("✅ Control frame from DOWNSTREAM origin correctly forwarded upstream")

    print("\n🎉 All tests passed! Loop prevention is working correctly.")
    return True


if __name__ == "__main__":
    result = asyncio.run(test_upstream_loop_prevention())
    if result:
        print("\n✅ Loop prevention implementation is correct!")
        exit(0)
    else:
        print("\n❌ Loop prevention implementation has issues!")
        exit(1)
