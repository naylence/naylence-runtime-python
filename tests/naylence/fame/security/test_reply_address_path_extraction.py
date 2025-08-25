#!/usr/bin/env python
"""
Test physical path extraction from reply addresses in key requests.

This test validates that sentinels can resolve encryption keys for addresses
like "rpc-sessionId@/physical/path" by extracting the physical path component.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import DeliveryOriginType, FameAddress, FameDeliveryContext
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler


@pytest.mark.asyncio
async def test_reply_address_path_extraction():
    """Test extraction of physical path from reply addresses for key lookup."""
    print("Testing reply address physical path extraction...")

    # Create a mock key store with a client's encryption key
    key_store = InMemoryKeyStore()
    client_physical_path = "/w3YI3dnHsQnuENw/mksnrwhAGPX8Rxn"
    client_encryption_key = {
        "kty": "OKP",
        "crv": "X25519",
        "x": "OUN06llYA1Vd5DprpjAMvyVwveQMANZMDfXFh_1qHnI",
        "kid": "sJZJT1Gqj4Hlzbj",
        "use": "enc",
        "alg": "ECDH-ES",
        "physical_path": client_physical_path,
    }

    # Add the client's encryption key to the key store
    await key_store.add_key("sJZJT1Gqj4Hlzbj", client_encryption_key)

    # Create mock key manager
    key_manager = Mock()
    key_manager._key_store = key_store
    key_manager.handle_key_request = AsyncMock()
    key_manager._envelope_factory_fn = Mock()
    # Mock the interface method to return the key from the store (async)
    key_manager.get_keys_for_path = AsyncMock(return_value=[client_encryption_key])

    # Create mock route manager
    route_manager = Mock()
    route_manager._downstream_addresses_routes = {}
    route_manager._peer_addresses_routes = {}

    # Create mock routing node
    routing_node = Mock()
    routing_node.id = "test-routing-node-id"  # Add proper string ID
    routing_node.forward_upstream = AsyncMock()
    routing_node.physical_path = client_physical_path  # Set the physical path

    # Create mock binding manager
    binding_manager = Mock()
    # Set up binding manager to return a binding for the reply address
    binding_manager.get_binding.return_value = Mock()  # Mock binding object

    # Create key frame handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=AsyncMock(),
    )

    # Test address extraction from a reply address
    reply_address = FameAddress("rpc-ZyjVUJVJJhvFMFg@/w3YI3dnHsQnuENw/mksnrwhAGPX8Rxn")

    # Call the address-based key request handler
    from naylence.fame.core import FameDeliveryContext

    downstream_context = FameDeliveryContext(
        from_system_id="test-sender", origin_type=DeliveryOriginType.DOWNSTREAM
    )
    await handler._handle_key_request_by_address(
        address=reply_address,
        from_seg="test-sender",
        physical_path=None,
        delivery_context=downstream_context,
        corr_id="test-correlation-123",
    )

    # Verify that handle_key_request was called with the correct parameters
    key_manager.handle_key_request.assert_called_once()
    call_args = key_manager.handle_key_request.call_args

    # Check the arguments
    assert call_args.kwargs["kid"] == "sJZJT1Gqj4Hlzbj"
    assert call_args.kwargs["from_seg"] == "test-sender"
    assert call_args.kwargs["physical_path"] == client_physical_path
    assert call_args.kwargs["origin"] == DeliveryOriginType.DOWNSTREAM
    assert call_args.kwargs["corr_id"] == "test-correlation-123"

    print("✅ Reply address physical path extraction test passed")
    return True


@pytest.mark.asyncio
async def test_regular_address_no_extraction():
    """Test that regular addresses (not reply addresses) don't trigger path extraction."""
    print("Testing regular address (no path extraction)...")

    # Create empty key store
    key_store = InMemoryKeyStore()

    # Create mock key manager
    key_manager = Mock()
    key_manager._key_store = key_store
    key_manager.handle_key_request = AsyncMock()
    key_manager.get_keys_for_path = AsyncMock(return_value=[])  # Mock the interface method

    # Create mock route manager
    route_manager = Mock()
    route_manager._downstream_addresses_routes = {}
    route_manager._peer_addresses_routes = {}

    # Create mock routing node
    routing_node = Mock()
    routing_node.id = "test-routing-node-id-2"  # Add proper string ID
    routing_node.forward_upstream = AsyncMock()
    routing_node.envelope_factory = Mock()
    mock_envelope = Mock()
    routing_node.envelope_factory.create_envelope.return_value = mock_envelope

    # Create mock binding manager
    binding_manager = Mock()

    # Create key frame handler
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=AsyncMock(),
    )

    # Test with a regular address that doesn't contain a physical path
    regular_address = FameAddress("math@/")

    # Call the address-based key request handler
    downstream_context = FameDeliveryContext(
        from_system_id="test-sender", origin_type=DeliveryOriginType.DOWNSTREAM
    )
    result = await handler._handle_key_request_by_address(
        address=regular_address,
        from_seg="test-sender",
        physical_path=None,
        delivery_context=downstream_context,
        corr_id="test-correlation-456",
    )

    # Verify that handle_key_request was NOT called (no key found)
    key_manager.handle_key_request.assert_not_called()

    # Verify that the request needs routing (returns False) for upstream forwarding
    # This ensures it goes through the routing pipeline instead of direct forwarding
    assert result is False, "Expected False to indicate routing needed"

    # Verify that direct upstream forwarding was NOT called (routing pipeline handles it now)
    routing_node.forward_upstream.assert_not_called()

    print("✅ Regular address (no path extraction) test passed")
    return True
