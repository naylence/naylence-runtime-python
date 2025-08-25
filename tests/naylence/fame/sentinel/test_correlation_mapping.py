#!/usr/bin/env python3

"""
Test that correlation mapping works correctly for pool addresses after removing conditional check.
"""

import asyncio
from unittest.mock import AsyncMock, Mock

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyRequestFrame,
)
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler


async def test_correlation_mapping_for_pool_addresses():
    """Test that correlation mapping is stored for all address-based KeyRequests."""

    print("Testing correlation mapping for pool addresses...")

    # Create mock dependencies
    routing_node = Mock()
    route_manager = Mock()
    route_manager._downstream_addresses_routes = {}
    route_manager._peer_addresses_routes = {}

    binding_manager = Mock()
    binding_manager.get_binding.return_value = None  # No local binding

    key_manager = Mock()
    key_manager.get_keys_for_path = AsyncMock(return_value=[])  # Return empty list as async mock
    accept_key_announce_parent = AsyncMock()

    # Create key frame handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=accept_key_announce_parent,
        key_manager=key_manager,
    )

    # Test cases: different types of addresses that should all get correlation mapping
    test_cases = [
        ("math@fame.fabric", "pool address"),  # Pool address
        ("service@unknown.domain", "unknown address"),  # Unknown address
        ("api@/physical/path", "physical path"),  # Physical path address
    ]

    for address_str, description in test_cases:
        print(f"\n  Testing {description}: {address_str}")

        # Create KeyRequest frame
        corr_id = f"corr-{address_str.replace('@', '-').replace('/', '-')}"
        frame = KeyRequestFrame(
            address=FameAddress(address_str),
            physical_path="/test/path",
        )

        # Create envelope and context
        envelope = Mock()
        envelope.frame = frame
        envelope.corr_id = corr_id

        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="test-client-123"
        )

        # Check correlation map before call
        initial_size = handler._corr_map.size()

        # Call accept_key_request
        result = await handler.accept_key_request(envelope, context)

        # Verify correlation was stored
        final_size = handler._corr_map.size()
        correlation_stored = final_size > initial_size

        # Verify the specific correlation exists by checking if we can retrieve it
        corr_id = envelope.corr_id
        stored_origin = None
        if corr_id in handler._corr_map._data:
            stored_origin, _ = handler._corr_map._data[corr_id]

        if correlation_stored and stored_origin == "test-client-123":
            print(f"    ✅ PASS: Correlation stored for {description}")
            print(f"       corr_id: {corr_id}")
            print(f"       origin: {stored_origin}")
        else:
            print(f"    ❌ FAIL: Correlation NOT stored for {description}")
            print("       Expected origin: test-client-123")
            print(f"       Actual origin: {stored_origin}")
            print(f"       Map size change: {initial_size} -> {final_size}")

        # Verify that the request was delegated to routing pipeline (not handled locally)
        if not result:
            print("    ✅ PASS: Request delegated to routing pipeline")
        else:
            print("    ❌ FAIL: Request was handled locally (should be delegated)")

    print(f"\n  Final correlation map size: {handler._corr_map.size()}")
    print("✅ Correlation mapping test completed!")


if __name__ == "__main__":
    asyncio.run(test_correlation_mapping_for_pool_addresses())
