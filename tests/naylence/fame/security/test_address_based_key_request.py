#!/usr/bin/env python3
"""
Test script to verify address-based key request functionality in KeyFrameHandler
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyRequestFrame,
)
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler
from naylence.fame.sentinel.route_manager import AddressRouteInfo, RouteManager


@pytest.mark.asyncio
async def test_key_request_by_address_with_encryption_key_id():
    """Test key request by address when route has encryption_key_id."""
    print("Testing key request by address with encryption_key_id...")

    # Setup mocks
    routing_node = MagicMock()
    routing_node.id = "test-routing-node-id"  # Ensure ID is a string
    routing_node.forward_to_route = AsyncMock()  # Make forward_to_route async
    key_manager = MagicMock(spec=KeyManager)
    key_manager.handle_key_request = AsyncMock()

    route_manager = MagicMock(spec=RouteManager)
    binding_manager = MagicMock()
    accept_key_announce_parent = AsyncMock()

    # Setup route info with encryption_key_id
    test_address = FameAddress("service@/test/path")
    test_encryption_key_id = "test-encryption-key-123"
    test_physical_path = "/test/physical/path"

    route_info = AddressRouteInfo(
        segment="test-segment",
        physical_path=test_physical_path,
        encryption_key_id=test_encryption_key_id,
    )

    route_manager._downstream_addresses_routes = {test_address: route_info}
    route_manager._peer_addresses_routes = {}

    # Create handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=accept_key_announce_parent,
    )

    # Create test frame and context
    frame = KeyRequestFrame(address=test_address)
    envelope = MagicMock()
    envelope.frame = frame
    envelope.corr_id = "test-corr-id"
    context = MagicMock(spec=FameDeliveryContext)
    context.origin_type = DeliveryOriginType.DOWNSTREAM
    context.from_system_id = "test-sender"

    # Execute the test
    result = await handler.accept_key_request(envelope, context)

    # Verify that the request needs routing (returns False) instead of being handled locally
    # This ensures it goes through the routing pipeline for deterministic SID routing
    assert result is False, "Expected False to indicate routing needed"

    # Verify that direct forwarding was NOT called (routing pipeline handles it now)
    routing_node.forward_to_route.assert_not_called()

    print("✅ Key request by address with encryption_key_id test passed")


@pytest.mark.asyncio
async def test_key_request_by_address_fallback_to_physical_path():
    """Test key request by address when route has no encryption_key_id but has physical path."""
    print("Testing key request by address fallback to physical path...")

    # Setup mocks
    routing_node = MagicMock()
    routing_node.id = "test-routing-node-id"  # Ensure ID is a string
    routing_node.forward_to_route = AsyncMock()  # Make forward_to_route async
    # Set the physical_path to the expected value
    test_physical_path = "/test/physical/path"
    routing_node.physical_path = test_physical_path

    key_manager = MagicMock(spec=KeyManager)
    key_manager.handle_key_request = AsyncMock()

    # Mock key manager to return keys for physical path
    mock_key = {"kid": "found-key-456", "use": "enc"}
    key_manager.get_keys_for_path.return_value = [mock_key]

    route_manager = MagicMock(spec=RouteManager)
    binding_manager = MagicMock()
    # Set up binding manager to return a local binding for the test address
    test_address = FameAddress("service@/test/path")
    binding_manager.get_binding.return_value = (
        MagicMock()
    )  # Return a mock binding to indicate local binding exists

    accept_key_announce_parent = AsyncMock()

    # Setup route info without encryption_key_id but with physical path
    # Remove the segment to make it a local route, not a forwarding route
    route_info = AddressRouteInfo(
        segment=None,  # No segment means local handling
        physical_path=test_physical_path,
        encryption_key_id=None,  # No encryption_key_id
    )

    route_manager._downstream_addresses_routes = {test_address: route_info}
    route_manager._peer_addresses_routes = {}

    # Create handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=accept_key_announce_parent,
    )

    # Create test frame and context
    frame = KeyRequestFrame(address=test_address)
    envelope = MagicMock()
    envelope.frame = frame
    envelope.corr_id = "test-corr-id"
    context = MagicMock(spec=FameDeliveryContext)
    context.origin_type = DeliveryOriginType.DOWNSTREAM
    context.from_system_id = "test-sender"

    # Execute the test
    await handler.accept_key_request(envelope, context)

    # Verify that get_keys_for_path was called with the routing node's physical path
    # (since we set up a local binding, it should use the node's own physical path)
    key_manager.get_keys_for_path.assert_called_once_with(test_physical_path)
    key_manager.handle_key_request.assert_called_once_with(
        kid="found-key-456",
        from_seg="test-sender",
        physical_path=test_physical_path,
        origin=DeliveryOriginType.DOWNSTREAM,
        corr_id="test-corr-id",
        original_client_sid=envelope.sid,  # Include the new parameter
    )

    print("✅ Key request by address fallback to physical path test passed")


@pytest.mark.asyncio
async def test_key_request_by_address_propagate_upstream():
    """Test key request by address when no local route is found - should propagate upstream."""
    print("Testing key request by address propagate upstream...")

    # Setup mocks
    routing_node = MagicMock()
    routing_node.id = "test-routing-node-id"  # Add proper string ID
    routing_node.forward_upstream = AsyncMock()
    routing_node.envelope_factory = MagicMock()

    # Mock envelope factory
    mock_envelope = MagicMock()
    routing_node.envelope_factory.create_envelope.return_value = mock_envelope

    key_manager = MagicMock(spec=KeyManager)

    route_manager = MagicMock()  # Remove spec to allow arbitrary attributes
    binding_manager = MagicMock()
    binding_manager.get_binding.return_value = None  # No local binding
    accept_key_announce_parent = AsyncMock()

    # Setup empty route tables
    route_manager._downstream_addresses_routes = {}
    route_manager._peer_addresses_routes = {}

    # Mock pool resolution to return empty list (no pool members found)
    route_manager.resolve_logical_address.return_value = []

    # Create handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=accept_key_announce_parent,
    )

    # Create test frame and context
    test_address = FameAddress("unknown@/unknown/path")
    frame = KeyRequestFrame(address=test_address)
    envelope = MagicMock()
    envelope.frame = frame
    envelope.corr_id = "test-corr-id"
    context = MagicMock(spec=FameDeliveryContext)
    context.origin_type = DeliveryOriginType.DOWNSTREAM
    context.from_system_id = "test-sender"

    # Execute the test
    result = await handler.accept_key_request(envelope, context)

    # Verify that the request needs routing (returns False) instead of being handled locally
    # This ensures upstream forwarding goes through the routing pipeline
    assert result is False, "Expected False to indicate routing needed"

    # Verify that direct upstream forwarding was NOT called (routing pipeline handles it now)
    routing_node.forward_upstream.assert_not_called()

    print("✅ Key request by address propagate upstream test passed")


@pytest.mark.asyncio
async def test_key_request_by_kid_still_works():
    """Test that key request by kid still works as before."""
    print("Testing key request by kid still works...")

    # Setup mocks
    routing_node = MagicMock()
    routing_node.id = "test-routing-node-id"  # Ensure ID is a string
    routing_node.forward_to_route = AsyncMock()  # Make forward_to_route async
    key_manager = MagicMock(spec=KeyManager)
    key_manager.handle_key_request = AsyncMock()

    route_manager = MagicMock(spec=RouteManager)
    binding_manager = MagicMock()
    accept_key_announce_parent = AsyncMock()

    # Create handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=accept_key_announce_parent,
    )

    # Create test frame and context with kid (not address)
    test_kid = "test-key-id-123"
    frame = KeyRequestFrame(kid=test_kid)
    envelope = MagicMock()
    envelope.frame = frame
    envelope.corr_id = "test-corr-id"
    context = MagicMock(spec=FameDeliveryContext)
    context.origin_type = DeliveryOriginType.DOWNSTREAM
    context.from_system_id = "test-sender"

    # Execute the test
    await handler.accept_key_request(envelope, context)

    # Verify that handle_key_request was called with the kid
    key_manager.handle_key_request.assert_called_once_with(
        kid=test_kid,
        from_seg="test-sender",
        physical_path=None,
        origin=DeliveryOriginType.DOWNSTREAM,
        corr_id="test-corr-id",
        original_client_sid=envelope.sid,  # Include the new parameter
    )

    print("✅ Key request by kid still works test passed")
