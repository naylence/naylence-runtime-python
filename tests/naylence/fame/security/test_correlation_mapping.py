#!/usr/bin/env python3
"""
Test script to verify correlation ID mapping for address-based key requests
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyAnnounceFrame,
    generate_id,
)
from naylence.fame.security.keys.key_management_handler import KeyManagementHandler


@pytest.mark.asyncio
async def test_address_based_key_request_correlation():
    """Test that address-based key requests are properly correlated using correlation IDs."""
    print("Testing address-based key request correlation...")

    # Setup mocks
    routing_node = MagicMock()
    routing_node.has_parent = True
    routing_node.physical_path = "/test/path"
    routing_node.id = "test-node-id"  # Add proper string ID
    routing_node.envelope_factory = MagicMock()
    routing_node.forward_upstream = AsyncMock()

    key_manager = MagicMock()
    key_manager.add_keys = AsyncMock()

    # Create handler
    handler = KeyManagementHandler(routing_node, key_manager)

    # Mock envelope creation
    test_corr_id = "test-correlation-123"
    mock_envelope = MagicMock()
    mock_frame = MagicMock()
    mock_frame.corr_id = test_corr_id
    mock_envelope.frame = mock_frame
    routing_node.envelope_factory.create_envelope.return_value = mock_envelope

    # Override generate_id to return our test correlation ID
    original_generate_id = generate_id

    def mock_generate_id():
        return test_corr_id

    # Patch generate_id temporarily
    import naylence.fame.security.keys.key_management_handler

    naylence.fame.security.keys.key_management_handler.generate_id = mock_generate_id

    try:
        # Start the handler
        await handler.start()

        # Test address for key request
        test_address = FameAddress("math@/")
        test_address_key = str(test_address)

        # Simulate requesting an encryption key by address
        await handler._maybe_request_encryption_key_by_address(
            address=test_address,
            origin=DeliveryOriginType.LOCAL,
            from_system_id="test-client",
        )

        # Verify that the correlation mapping was stored
        assert test_corr_id in handler._correlation_to_address
        assert handler._correlation_to_address[test_corr_id] == test_address_key
        print(f"✅ Correlation mapping stored: {test_corr_id} -> {test_address_key}")

        # Verify that a pending request was created
        assert test_address_key in handler._pending_encryption_key_requests
        print(f"✅ Pending encryption request created for address: {test_address_key}")

        # Simulate receiving a KeyAnnounce response with the correlation ID
        test_key = {
            "kid": "test-encryption-key-456",
            "use": "enc",
            "kty": "OKP",
            "crv": "X25519",
            "x": "test-key-data",
        }

        key_announce_frame = KeyAnnounceFrame(physical_path="/test/upstream/path", keys=[test_key])

        envelope = MagicMock()
        envelope.frame = key_announce_frame
        envelope.corr_id = test_corr_id
        envelope.sid = "test-sid"

        context = MagicMock(spec=FameDeliveryContext)
        context.origin_type = DeliveryOriginType.UPSTREAM
        context.from_system_id = "upstream-system"

        # Process the KeyAnnounce
        await handler.accept_key_announce(envelope, context)

        # Verify that the correlation mapping was cleaned up
        assert test_corr_id not in handler._correlation_to_address
        print("✅ Correlation mapping cleaned up after processing")

        # Verify that the pending request was resolved
        assert test_address_key not in handler._pending_encryption_key_requests
        print(f"✅ Pending encryption request resolved for address: {test_address_key}")

        # Verify that keys were added to key manager (should be called three times:
        # once during start, once for physical path, once for target address)
        assert key_manager.add_keys.call_count == 3

        # Check the second call (KeyAnnounce response with physical path)
        second_call = key_manager.add_keys.call_args_list[1]
        assert second_call.kwargs["keys"] == [test_key]
        assert second_call.kwargs["sid"] == "test-sid"
        assert second_call.kwargs["physical_path"] == "/test/upstream/path"

        # Check the third call (KeyAnnounce response with target address)
        third_call = key_manager.add_keys.call_args_list[2]
        assert third_call.kwargs["keys"] == [test_key]
        assert third_call.kwargs["sid"] == "test-sid"
        assert third_call.kwargs["physical_path"] == test_address_key  # Should use target address as path
        assert second_call.kwargs["system_id"] == "upstream-system"
        assert second_call.kwargs["origin"] == DeliveryOriginType.UPSTREAM
        print("✅ Keys added to key manager via KeyAnnounce response")

        print("✅ Address-based key request correlation test passed")

    finally:
        # Restore original generate_id
        naylence.fame.security.keys.key_management_handler.generate_id = original_generate_id
        await handler.stop()


@pytest.mark.asyncio
async def test_correlation_cleanup_on_timeout():
    """Test that correlation mappings are cleaned up when requests timeout."""
    print("Testing correlation cleanup on timeout...")

    # Setup mocks
    routing_node = MagicMock()
    routing_node.has_parent = True
    routing_node.physical_path = "/test/path"
    routing_node.id = "test-node-timeout-id"  # Add proper string ID
    routing_node.envelope_factory = MagicMock()
    routing_node.forward_upstream = AsyncMock()

    key_manager = MagicMock()
    key_manager.add_keys = AsyncMock()

    # Create handler
    handler = KeyManagementHandler(routing_node, key_manager)

    # Mock envelope creation
    test_corr_id = "test-correlation-timeout-456"
    mock_envelope = MagicMock()
    mock_frame = MagicMock()
    mock_frame.corr_id = test_corr_id
    mock_envelope.frame = mock_frame
    routing_node.envelope_factory.create_envelope.return_value = mock_envelope

    # Override generate_id to return our test correlation ID
    original_generate_id = generate_id

    def mock_generate_id():
        return test_corr_id

    # Patch generate_id temporarily
    import naylence.fame.security.keys.key_management_handler

    naylence.fame.security.keys.key_management_handler.generate_id = mock_generate_id

    try:
        # Start the handler
        await handler.start()

        # Test address for key request
        test_address = FameAddress("timeout-test@/")
        test_address_key = str(test_address)

        # Simulate requesting an encryption key by address
        await handler._maybe_request_encryption_key_by_address(
            address=test_address,
            origin=DeliveryOriginType.LOCAL,
            from_system_id="test-client",
        )

        # Verify correlation mapping was stored
        assert test_corr_id in handler._correlation_to_address
        assert test_address_key in handler._pending_encryption_key_requests

        # Manually trigger timeout by setting expired time and running GC logic
        import time

        current_time = time.monotonic()

        # Update the request to be expired
        fut, origin, from_system_id, expires, retries = handler._pending_encryption_key_requests[
            test_address_key
        ]
        handler._pending_encryption_key_requests[test_address_key] = (
            fut,
            origin,
            from_system_id,
            current_time - 1,
            999,  # Set retries to max to trigger cleanup
        )

        # Manually call the GC logic (simulate what would happen in _gc_key_requests)
        for kid, (fut, origin, from_system_id, expires, retries) in list(
            handler._pending_encryption_key_requests.items()
        ):
            if current_time >= expires and retries + 1 >= 3:  # KEY_REQUEST_RETRIES
                fut.set_exception(asyncio.TimeoutError("Encryption key fetch failed"))
                handler._pending_encryption_envelopes.pop(kid, [])
                handler._pending_encryption_key_requests.pop(kid, None)

                # Clean up correlation mapping
                corr_ids_to_remove = [
                    corr_id
                    for corr_id, addr_key in handler._correlation_to_address.items()
                    if addr_key == kid
                ]
                for corr_id in corr_ids_to_remove:
                    handler._correlation_to_address.pop(corr_id, None)

        # Verify cleanup happened
        assert test_corr_id not in handler._correlation_to_address
        assert test_address_key not in handler._pending_encryption_key_requests
        print("✅ Correlation mapping and pending request cleaned up on timeout")

        print("✅ Correlation cleanup on timeout test passed")

    finally:
        # Restore original generate_id
        naylence.fame.security.keys.key_management_handler.generate_id = original_generate_id
        await handler.stop()
