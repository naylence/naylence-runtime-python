#!/usr/bin/env python3

"""
Test the pool resolution functionality through the routing policy.
"""

import asyncio
from typing import Any
from unittest.mock import Mock

from naylence.fame.core import FameAddress, KeyRequestFrame

# Import routing components
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.load_balancing.hrw_load_balancing_strategy import (
    HRWLoadBalancingStrategy,
)
from naylence.fame.sentinel.router import RouterState


# Mock envelope factory
class MockEnvelopeFactory:
    def create_envelope(self, trace_id: str, frame: Any, flow_id: str):
        envelope = Mock()
        envelope.trace_id = trace_id
        envelope.frame = frame
        envelope.flow_id = flow_id
        envelope.sid = "test-sid-123"
        return envelope


async def test_pool_resolution():
    """Test pool resolution functionality through the routing policy."""

    # Set up pools with proper wildcard patterns
    # Pool patterns must start with '*.' to be considered logical pools
    pools = {
        ("math", "*.fabric"): {"child-a", "child-b"},  # Wildcard match for *.fabric
        ("agent", "*.fabric"): {
            "sentinel-1",
            "sentinel-2",
        },  # Wildcard match for *.fabric
        ("*", "*.domain"): {"fallback-node"},  # Catch-all for *.domain
    }

    # Create router state
    router_state = RouterState(
        node_id="test-node",
        physical_segments=["self", "child-a", "child-b", "sentinel-1", "sentinel-2"],
        downstream_address_routes={},
        peer_address_routes={},
        child_segments={
            "child-a",
            "child-b",
            "sentinel-1",
            "sentinel-2",
            "fallback-node",
        },
        peer_segments=set(),
        has_parent=True,
        pools=pools,
        local=set(),
    )

    # Create routing policy with load balancer
    load_balancer = HRWLoadBalancingStrategy()
    routing_policy = HybridPathRoutingPolicy(load_balancer)

    # Create mock envelope factory
    envelope_factory = MockEnvelopeFactory()

    print("Testing pool resolution through routing policy...")

    # Test cases: logical address -> expected behavior
    test_cases = [
        ("math@fame.fabric", ["child-a", "child-b"]),  # Should route to a pool member
        (
            "agent@fame.fabric",
            ["sentinel-1", "sentinel-2"],
        ),  # Should route to a pool member
        ("unknown@fame.fabric", None),  # Should return ForwardUp (no matching pool)
        (
            "math@other.domain",
            None,
        ),  # Should return ForwardUp (doesn't match pool pattern)
    ]

    for logical_address, expected_members in test_cases:
        # Create a KeyRequest envelope
        frame = KeyRequestFrame(
            corr_id="test-corr-id",
            address=FameAddress(logical_address),
            physical_path="/test/path",
        )

        # Create test envelope
        envelope = envelope_factory.create_envelope(
            trace_id="test-trace-id", frame=frame, flow_id="test-flow-id"
        )

        # Get routing decision from policy
        routing_action = await routing_policy.decide(envelope, router_state)

        if expected_members is None:
            # Should route upstream
            success = routing_action.__class__.__name__ == "ForwardUp"
            result = "PASS" if success else "FAIL"
            print(f"  {logical_address} -> ForwardUp: {result}")
            if not success:
                print(f"    Expected ForwardUp, got: {routing_action}")
        else:
            # Should route to a child (pool member)
            success = (
                routing_action.__class__.__name__ == "ForwardChild"
                and routing_action.segment in expected_members
            )
            result = "PASS" if success else "FAIL"
            member = routing_action.segment if hasattr(routing_action, "segment") else str(routing_action)
            print(f"  {logical_address} -> {member}: {result}")
            if not success:
                print(f"    Expected ForwardChild to one of {expected_members}, got: {routing_action}")

    print("✅ Pool resolution through routing policy tests completed!")


if __name__ == "__main__":
    asyncio.run(test_pool_resolution())
