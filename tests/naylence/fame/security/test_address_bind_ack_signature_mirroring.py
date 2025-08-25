#!/usr/bin/env python3
"""
Test that AddressBindAck responses are properly signed when the original AddressBind request was signed.
This tests the signature mirroring functionality for address binding protocol.
"""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import (
    AddressBindAckFrame,
    AddressBindFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.sentinel.address_bind_frame_handler import AddressBindFrameHandler


@pytest.mark.asyncio
async def test_address_bind_ack_signature_mirroring():
    """Test that AddressBindAck responses are signed when AddressBind requests are signed."""
    print("🧪 Testing AddressBindAck signature mirroring...")

    # Setup mocks
    routing_node = Mock()
    routing_node.forward_to_route = AsyncMock()
    routing_node.forward_upstream = AsyncMock()
    routing_node.forward_to_peers = AsyncMock()

    # Mock envelope factory
    mock_ack_envelope = Mock()
    routing_node.envelope_factory.create_envelope.return_value = mock_ack_envelope

    route_manager = Mock()
    route_manager.downstream_routes = {"test-client": Mock()}
    route_manager._downstream_route_store.get.return_value = Mock(assigned_path="/test/path")
    route_manager._downstream_addresses_routes = {}
    route_manager._downstream_addresses_legacy = {}

    upstream_connector = Mock(return_value=True)

    # Create handler
    handler = AddressBindFrameHandler(
        routing_node=routing_node,
        route_manager=route_manager,
        upstream_connector=upstream_connector,
    )

    # Create signed AddressBind request
    address_bind_frame = AddressBindFrame(
        address=FameAddress("service@/test/path"),
        encryption_key_id="test-key-456",
    )

    # Create envelope for the signed request
    signed_envelope = FameEnvelope(
        id=generate_id(),
        frame=address_bind_frame,
        corr_id="test-corr-123",
    )

    # Add signature to indicate this was a signed request
    signed_envelope.sec = Mock()
    signed_envelope.sec.sig = Mock()
    signed_envelope.sec.sig.kid = "test-signing-key"
    signed_envelope.sec.sig.val = b"signature-bytes"

    # Create context indicating a signed downstream request
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="test-client",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.PLAINTEXT,
            inbound_was_signed=True,  # The original request was signed
        ),
    )

    print(f"📝 Original request signed: {context.security.inbound_was_signed}")
    print(f"📝 Original crypto level: {context.security.inbound_crypto_level}")

    # Execute the handler
    await handler.accept_address_bind(signed_envelope, context)

    # Verify that forward_to_route was called (ACK sent back)
    routing_node.forward_to_route.assert_called_once()
    call_args = routing_node.forward_to_route.call_args

    # Check the arguments passed to forward_to_route
    sent_segment = call_args[0][0]
    sent_envelope = call_args[0][1]
    sent_context = call_args[0][2]

    print(f"📤 ACK sent to segment: {sent_segment}")
    print(f"📤 ACK envelope: {sent_envelope}")
    print(f"📤 ACK context: {sent_context}")

    # Verify the context passed to forward_to_route has correct properties for signature mirroring
    assert (
        sent_context is not context
    ), "Should create a new LOCAL context, not reuse the original DOWNSTREAM context"
    assert sent_context.origin_type == DeliveryOriginType.LOCAL, "ACK should use LOCAL origin type"
    assert sent_context.from_system_id == "sentinel", "ACK should come from the sentinel"
    assert (
        sent_context.security.inbound_was_signed
    ), "Context should preserve that original request was signed"
    assert (
        sent_context.security.inbound_crypto_level == CryptoLevel.PLAINTEXT
    ), "Context should preserve crypto level"
    assert (
        sent_context.meta.get("message-type") == "response"
    ), "Context should be marked as response for signature mirroring"

    print("✅ AddressBindAck context correctly configured for signature mirroring")

    # Verify envelope factory was called correctly
    routing_node.envelope_factory.create_envelope.assert_called_once()
    envelope_call_args = routing_node.envelope_factory.create_envelope.call_args

    # Check that the frame is AddressBindAckFrame
    created_frame = envelope_call_args.kwargs["frame"]
    assert isinstance(created_frame, AddressBindAckFrame)
    assert created_frame.address == FameAddress("service@/test/path")
    assert created_frame.ok is True

    # Check that corr_id was passed to envelope creation
    assert envelope_call_args.kwargs["corr_id"] == "test-corr-123"

    print("✅ AddressBindAck frame correctly created")


@pytest.mark.asyncio
async def test_address_bind_ack_no_signature_mirroring_for_unsigned_request():
    """Test that AddressBindAck responses are not signed when AddressBind requests are unsigned."""
    print("🧪 Testing AddressBindAck with unsigned request (no mirroring)...")

    # Setup mocks
    routing_node = Mock()
    routing_node.forward_to_route = AsyncMock()
    routing_node.forward_upstream = AsyncMock()
    routing_node.forward_to_peers = AsyncMock()

    # Mock envelope factory
    mock_ack_envelope = Mock()
    routing_node.envelope_factory.create_envelope.return_value = mock_ack_envelope

    route_manager = Mock()
    route_manager.downstream_routes = {"test-client": Mock()}
    route_manager._downstream_route_store.get.return_value = Mock(assigned_path="/test/path")
    route_manager._downstream_addresses_routes = {}
    route_manager._downstream_addresses_legacy = {}

    upstream_connector = Mock(return_value=True)

    # Create handler
    handler = AddressBindFrameHandler(
        routing_node=routing_node,
        route_manager=route_manager,
        upstream_connector=upstream_connector,
    )

    # Create unsigned AddressBind request
    address_bind_frame = AddressBindFrame(
        address=FameAddress("service@/test/path"),
    )

    # Create envelope for the unsigned request (no .sec section)
    unsigned_envelope = FameEnvelope(
        id=generate_id(),
        frame=address_bind_frame,
        corr_id="test-corr-789",
    )

    # Create context indicating an unsigned downstream request
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="test-client",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.PLAINTEXT,
            inbound_was_signed=False,  # The original request was NOT signed
        ),
    )

    print(f"📝 Original request signed: {context.security.inbound_was_signed}")

    # Execute the handler
    await handler.accept_address_bind(unsigned_envelope, context)

    # Verify that forward_to_route was called (ACK sent back)
    routing_node.forward_to_route.assert_called_once()
    call_args = routing_node.forward_to_route.call_args

    # Check the context passed to forward_to_route
    sent_context = call_args[0][2]
    assert (
        sent_context is not context
    ), "Should create a new LOCAL context, not reuse the original DOWNSTREAM context"
    assert sent_context.origin_type == DeliveryOriginType.LOCAL, "ACK should use LOCAL origin type"
    assert (
        sent_context.security.inbound_was_signed is False
    ), "Context should preserve that original request was unsigned"
    assert sent_context.meta.get("message-type") == "response", "Context should be marked as response"

    print("✅ AddressBindAck context correctly indicates no signature mirroring needed")


if __name__ == "__main__":
    asyncio.run(test_address_bind_ack_signature_mirroring())
    asyncio.run(test_address_bind_ack_no_signature_mirroring_for_unsigned_request())
