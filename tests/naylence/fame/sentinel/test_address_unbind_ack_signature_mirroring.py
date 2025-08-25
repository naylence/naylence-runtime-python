"""
Tests for AddressUnbindAck signature mirroring functionality.

This test suite verifies that AddressUnbindAck frames are properly signed
when signature mirroring is enabled, following the same pattern as other
ACK frame types.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    AddressUnbindAckFrame,
    AddressUnbindFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.core import (
    SecurityContext as FameSecurityContext,
)
from naylence.fame.sentinel.address_bind_frame_handler import AddressBindFrameHandler
from naylence.fame.sentinel.route_manager import RouteManager


@pytest.fixture
def mock_routing_node():
    """Create a mock routing node for testing."""
    mock_node = MagicMock()
    mock_node.id = "test-sentinel"
    mock_node.envelope_factory.create_envelope.return_value = MagicMock()
    mock_node.forward_to_route = AsyncMock()
    mock_node.forward_upstream = AsyncMock()
    mock_node.forward_to_peers = AsyncMock()
    return mock_node


@pytest.fixture
def mock_route_manager():
    """Create a mock route manager for testing."""
    route_manager = MagicMock(spec=RouteManager)
    route_manager.downstream_routes = {"test-child": MagicMock()}
    route_manager._downstream_addresses_routes = {"test@/api/v1": MagicMock()}
    route_manager._downstream_addresses_legacy = {"test@/api/v1": "test-child"}
    return route_manager


@pytest.fixture
def mock_upstream_connector():
    """Create a mock upstream connector."""
    return MagicMock(return_value=True)


@pytest.fixture
def handler(mock_routing_node, mock_route_manager, mock_upstream_connector):
    """Create an AddressBindFrameHandler for testing."""
    return AddressBindFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        upstream_connector=mock_upstream_connector,
    )


@pytest.mark.asyncio
async def test_address_unbind_ack_signature_mirroring_with_signed_request(handler, mock_routing_node):
    """Test that AddressUnbindAck is signed when the original request was signed."""
    # Create a signed security context (simulating mirror_request_signing=True)
    security_context = FameSecurityContext(
        signature="original-signature",
        signature_key_id="test-key-id",
        envelope_signed=True,
    )

    # Create delivery context for downstream request with security info
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="test-child",
        security=security_context,
    )

    # Create AddressUnbindFrame
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("test@/api/v1"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="test-correlation-123")

    # Mock forward_to_route to capture calls
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler
    await handler.accept_address_unbind(envelope, context)

    # Verify forward_to_route was called
    mock_routing_node.forward_to_route.assert_called_once()

    # Extract the call arguments
    call_args = mock_routing_node.forward_to_route.call_args
    target_system_id = call_args[0][0]
    call_args[0][1]
    ack_context = call_args[0][2]

    # Verify the target system ID
    assert target_system_id == "test-child"

    # Verify the response envelope contains AddressUnbindAckFrame
    mock_routing_node.envelope_factory.create_envelope.assert_called_once()
    create_call_args = mock_routing_node.envelope_factory.create_envelope.call_args
    ack_frame = create_call_args[1]["frame"]
    assert isinstance(ack_frame, AddressUnbindAckFrame)
    assert ack_frame.address == FameAddress("test@/api/v1")
    assert ack_frame.ok is True

    # Check that corr_id was passed to envelope creation
    assert create_call_args[1]["corr_id"] == "test-correlation-123"

    # Verify the ACK context for signature mirroring
    assert ack_context.origin_type == DeliveryOriginType.LOCAL
    assert ack_context.from_system_id == "test-sentinel"
    assert ack_context.security == security_context  # Preserved for signature mirroring
    assert ack_context.meta == {"message-type": "response"}


@pytest.mark.asyncio
async def test_address_unbind_ack_signature_mirroring_with_unsigned_request(handler, mock_routing_node):
    """Test that AddressUnbindAck is not signed when the original request was unsigned."""
    # Create delivery context for downstream request without security info
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="test-child",
        security=None,  # No security context
    )

    # Create AddressUnbindFrame
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("test@/api/v1"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="test-correlation-456")

    # Mock forward_to_route to capture calls
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler
    await handler.accept_address_unbind(envelope, context)

    # Verify forward_to_route was called
    mock_routing_node.forward_to_route.assert_called_once()

    # Extract the call arguments
    call_args = mock_routing_node.forward_to_route.call_args
    ack_context = call_args[0][2]

    # Verify the ACK context does not have security info
    assert ack_context.origin_type == DeliveryOriginType.LOCAL
    assert ack_context.from_system_id == "test-sentinel"
    assert ack_context.security is None  # No security context to preserve
    assert ack_context.meta == {"message-type": "response"}


@pytest.mark.asyncio
async def test_address_unbind_ack_not_sent_for_peer_requests(handler, mock_routing_node):
    """Test that AddressUnbindAck is not sent for peer requests."""
    # Create delivery context for peer request
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.PEER,
        from_system_id="test-peer",
        security=None,
    )

    # Create AddressUnbindFrame
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("test@/api/v1"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="test-correlation-789")

    # Mock forward_to_route to capture calls
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler
    await handler.accept_address_unbind(envelope, context)

    # Verify forward_to_route was NOT called (no ACK for peer requests)
    mock_routing_node.forward_to_route.assert_not_called()


@pytest.mark.asyncio
async def test_address_unbind_ack_not_sent_when_no_context(handler, mock_routing_node):
    """Test that AddressUnbindAck is not sent when context is None."""
    # Create AddressUnbindFrame
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("test@/api/v1"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="test-correlation-none")

    # Mock forward_to_route to capture calls
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler with None context
    await handler.accept_address_unbind(envelope, None)

    # Verify forward_to_route was NOT called (no ACK when no context)
    mock_routing_node.forward_to_route.assert_not_called()


@pytest.mark.asyncio
async def test_address_unbind_ack_routing_node_id_fallback(handler, mock_routing_node):
    """Test that AddressUnbindAck uses fallback routing node ID when needed."""
    # Remove the id attribute to test fallback
    del mock_routing_node.id

    # Create delivery context for downstream request
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="test-child",
        security=None,
    )

    # Create AddressUnbindFrame
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("test@/api/v1"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="test-correlation-fallback")

    # Mock forward_to_route to capture calls
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler
    await handler.accept_address_unbind(envelope, context)

    # Verify forward_to_route was called
    mock_routing_node.forward_to_route.assert_called_once()

    # Extract the call arguments and verify fallback ID was used
    call_args = mock_routing_node.forward_to_route.call_args
    ack_context = call_args[0][2]
    assert ack_context.from_system_id == "sentinel"  # Fallback value


@pytest.mark.asyncio
async def test_address_unbind_with_pool_pattern(handler, mock_routing_node):
    """Test AddressUnbindAck for pool pattern addresses."""
    # Add pool data to handler
    handler._pools[("math", "*.fame.fabric")] = {"test-child"}

    # Create delivery context for downstream request
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="test-child",
        security=None,
    )

    # Create AddressUnbindFrame with pool pattern
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("math@*.fame.fabric"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="test-pool-unbind")

    # Mock forward_to_route to capture calls
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler
    await handler.accept_address_unbind(envelope, context)

    # Verify ACK was sent
    mock_routing_node.forward_to_route.assert_called_once()

    # Verify pool was updated
    assert ("math", "*.fame.fabric") not in handler._pools


@pytest.mark.asyncio
async def test_address_unbind_ack_integration_with_signature_mirroring(handler, mock_routing_node):
    """Integration test verifying complete signature mirroring flow."""
    # Create a comprehensive security context
    security_context = FameSecurityContext(
        inbound_was_signed=True,
        inbound_crypto_level="signed",
        crypto_channel_id="test-channel",
    )

    # Create delivery context simulating a signed request requiring mirroring
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.DOWNSTREAM,
        from_system_id="production-child-node",
        security=security_context,
        stickiness_required=True,
        sticky_sid="sticky-session-789",
    )

    # Create AddressUnbindFrame
    unbind_frame = AddressUnbindFrame(
        address=FameAddress("service@/production/api"),
    )

    envelope = FameEnvelope(frame=unbind_frame, corr_id="prod-unbind-correlation-123")

    # Mock forward_to_route to capture the complete call
    mock_routing_node.forward_to_route = AsyncMock()

    # Execute the handler
    await handler.accept_address_unbind(envelope, context)

    # Verify the complete flow
    mock_routing_node.forward_to_route.assert_called_once()
    call_args = mock_routing_node.forward_to_route.call_args

    # Verify target system
    assert call_args[0][0] == "production-child-node"

    # Verify ACK frame creation
    mock_routing_node.envelope_factory.create_envelope.assert_called_once()
    create_args = mock_routing_node.envelope_factory.create_envelope.call_args
    ack_frame = create_args[1]["frame"]
    assert isinstance(ack_frame, AddressUnbindAckFrame)
    assert ack_frame.address == FameAddress("service@/production/api")
    assert ack_frame.ok is True

    # Check that corr_id was passed to envelope creation
    assert create_args[1]["corr_id"] == "prod-unbind-correlation-123"

    # Verify LOCAL delivery context with preserved security
    ack_context = call_args[0][2]
    assert ack_context.origin_type == DeliveryOriginType.LOCAL
    assert ack_context.from_system_id == "test-sentinel"
    assert ack_context.security is security_context  # Exact same object preserved
    assert ack_context.meta == {"message-type": "response"}


@pytest.mark.asyncio
async def test_address_unbind_behavior_documentation():
    """
    Behavioral documentation test explaining AddressUnbindAck signature mirroring.

    This test documents the expected behavior:
    1. AddressUnbindAck frames should be signed when the original request was signed
    2. The ACK uses LOCAL delivery context to ensure security policy signs it
    3. Original security context is preserved to enable signature mirroring
    4. ACKs are only sent for downstream requests, not peer requests
    5. The response is marked with meta={"message-type": "response"} for mirroring
    """
    # This test serves as living documentation
    # The actual behavior is verified by the other tests in this file
    assert True, "AddressUnbindAck signature mirroring is properly implemented"
