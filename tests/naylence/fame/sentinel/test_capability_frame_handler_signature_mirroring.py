#!/usr/bin/env python3
"""
Tests for CapabilityFrameHandler signature mirroring functionality.

This tests the fix for the issue where CapabilityAdvertiseAck and CapabilityWithdrawAck
frames were not being signed even when mirror_request_signing was enabled in the security policy.

The root cause was that response envelopes were being forwarded with the original downstream
delivery context, but the security policy only signs LOCAL origin envelopes. The fix creates
a new LOCAL delivery context while preserving the security information needed for mirroring.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    CapabilityAdvertiseAckFrame,
    CapabilityAdvertiseFrame,
    CapabilityWithdrawFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    create_fame_envelope,
    generate_id,
)
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.sentinel.capability_frame_handler import CapabilityFrameHandler
from naylence.fame.sentinel.route_manager import RouteManager


class TestCapabilityFrameHandlerSignatureMirroring:
    """Test signature mirroring in CapabilityFrameHandler."""

    @pytest.fixture
    def mock_routing_node(self):
        """Create a mock routing node."""
        mock_node = MagicMock()
        mock_node.sid = "test-sentinel-123"

        # Mock envelope factory
        mock_envelope_factory = MagicMock()
        mock_node.envelope_factory = mock_envelope_factory

        # Make create_envelope return real envelopes
        def create_real_envelope(frame, corr_id=None):
            return create_fame_envelope(frame=frame, corr_id=corr_id)

        mock_envelope_factory.create_envelope.side_effect = create_real_envelope

        # Mock forward_to_route to capture calls
        mock_node.forward_to_route = AsyncMock()
        mock_node.forward_upstream = AsyncMock()

        return mock_node

    @pytest.fixture
    def mock_route_manager(self):
        """Create a mock route manager with registered downstream routes."""
        route_manager = MagicMock(spec=RouteManager)
        route_manager.downstream_routes = {
            "test-node-456": "mock-connector",
            "test-node-789": "mock-connector-2",
        }
        return route_manager

    @pytest.fixture
    def mock_upstream_connector(self):
        """Create a mock upstream connector."""
        return MagicMock(return_value=None)

    @pytest.fixture
    def capability_handler(self, mock_routing_node, mock_route_manager, mock_upstream_connector):
        """Create a CapabilityFrameHandler instance."""
        return CapabilityFrameHandler(
            routing_node=mock_routing_node,
            route_manager=mock_route_manager,
            upstream_connector=mock_upstream_connector,
        )

    @pytest.fixture
    def signed_request_context(self):
        """Create a delivery context indicating the request was signed."""
        return FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(inbound_was_signed=True, inbound_crypto_level="signed"),
        )

    @pytest.fixture
    def unsigned_request_context(self):
        """Create a delivery context for an unsigned request."""
        return FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            # No security context
        )

    @pytest.fixture
    def stickiness_context(self):
        """Create a delivery context with stickiness information."""
        return FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(inbound_was_signed=True),
            stickiness_required=True,
            sticky_sid="sticky-session-123",
        )

    async def test_capability_advertise_creates_local_context_for_signed_request(
        self, capability_handler, mock_routing_node, signed_request_context
    ):
        """Test that CapabilityAdvertise creates LOCAL context preserving security info for signed
        requests."""
        # Create capability advertise frame
        corr_id = generate_id()
        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.agent"],
            address=FameAddress("math@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, signed_request_context)

        # Verify forward_to_route was called
        mock_routing_node.forward_to_route.assert_called_once()

        # Extract the call arguments
        call_args = mock_routing_node.forward_to_route.call_args
        segment, response_envelope, response_context = call_args[0]

        # Verify the response context is LOCAL origin (key for signing)
        assert (
            response_context.origin_type == DeliveryOriginType.LOCAL
        ), "Response context must be LOCAL origin for security policy to sign it"

        # Verify security information is preserved for mirroring
        assert response_context.security is not None, "Security context should be preserved"
        assert (
            response_context.security.inbound_was_signed is True
        ), "inbound_was_signed should be preserved for signature mirroring"
        assert (
            response_context.security.inbound_crypto_level == "signed"
        ), "Crypto level should be preserved"

        # Verify the response envelope contains the correct frame
        assert isinstance(response_envelope.frame, CapabilityAdvertiseAckFrame)
        assert response_envelope.frame.ok is True
        assert response_envelope.corr_id == corr_id

    async def test_capability_advertise_creates_local_context_for_unsigned_request(
        self, capability_handler, mock_routing_node, unsigned_request_context
    ):
        """Test that CapabilityAdvertise creates LOCAL context even for unsigned requests."""
        # Create capability advertise frame
        corr_id = generate_id()
        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.test"],
            address=FameAddress("service@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, unsigned_request_context)

        # Verify forward_to_route was called
        mock_routing_node.forward_to_route.assert_called_once()

        # Extract the call arguments
        call_args = mock_routing_node.forward_to_route.call_args
        segment, response_envelope, response_context = call_args[0]

        # Verify the response context is LOCAL origin
        assert response_context.origin_type == DeliveryOriginType.LOCAL

        # Verify no security context is preserved (request was unsigned)
        assert response_context.security is None, "Security context should be None for unsigned requests"

    async def test_capability_advertise_preserves_stickiness_information(
        self, capability_handler, mock_routing_node, stickiness_context
    ):
        """Test that stickiness information is preserved in the response context."""
        # Create capability advertise frame
        corr_id = generate_id()
        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.sticky"],
            address=FameAddress("sticky@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, stickiness_context)

        # Verify forward_to_route was called
        mock_routing_node.forward_to_route.assert_called_once()

        # Extract the call arguments
        call_args = mock_routing_node.forward_to_route.call_args
        segment, response_envelope, response_context = call_args[0]

        # Verify the response context preserves stickiness information
        assert response_context.origin_type == DeliveryOriginType.LOCAL
        assert response_context.stickiness_required is True
        assert response_context.sticky_sid == "sticky-session-123"

        # Verify security context is also preserved
        assert response_context.security is not None
        assert response_context.security.inbound_was_signed is True

    async def test_capability_withdraw_creates_local_context_for_signed_request(
        self, capability_handler, mock_routing_node, signed_request_context
    ):
        """Test that CapabilityWithdraw creates LOCAL context preserving security info."""
        # Pre-register a capability to withdraw
        test_address = FameAddress("math@test-node-456.fame.fabric")
        capability_handler._cap_routes["fame.capability.agent"][test_address] = "test-node-456"

        # Create capability withdraw frame
        corr_id = generate_id()
        frame = CapabilityWithdrawFrame(
            capabilities=["fame.capability.agent"],
            address=test_address,
        )
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        # Call the handler
        await capability_handler.accept_capability_withdraw(envelope, signed_request_context)

        # Verify forward_to_route was called
        mock_routing_node.forward_to_route.assert_called_once()

        # Extract the call arguments
        call_args = mock_routing_node.forward_to_route.call_args
        segment, response_envelope, response_context = call_args[0]

        # FIXED BEHAVIOR: Now uses LOCAL context like advertise
        assert (
            response_context.origin_type == DeliveryOriginType.LOCAL
        ), "FIXED: Withdraw ACK now uses LOCAL origin for signing policy to apply"

        # Verify security information is preserved for mirroring
        assert response_context.security is not None
        assert response_context.security.inbound_was_signed is True

    async def test_capability_advertise_unknown_child_returns_early(
        self, capability_handler, mock_routing_node
    ):
        """Test that unknown child nodes are handled gracefully."""
        # Create context for unknown child
        unknown_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="unknown-node-999",  # Not in route_manager.downstream_routes
        )

        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.unknown"],
            address=FameAddress("unknown@unknown-node-999.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=generate_id())

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, unknown_context)

        # Verify no forwarding occurred
        mock_routing_node.forward_to_route.assert_not_called()

    async def test_capability_advertise_first_global_triggers_upstream_propagation(
        self, capability_handler, mock_routing_node, signed_request_context
    ):
        """Test that first global capability triggers upstream propagation."""
        # Mock upstream connector to return a connector
        capability_handler._upstream_connector = MagicMock(return_value="mock-upstream-connector")

        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.new"],  # New capability not seen before
            address=FameAddress("new@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=generate_id())

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, signed_request_context)

        # Verify downstream ACK was sent
        mock_routing_node.forward_to_route.assert_called_once()

        # Verify upstream propagation occurred
        mock_routing_node.forward_upstream.assert_called_once()
        upstream_call_args = mock_routing_node.forward_upstream.call_args
        upstream_envelope, upstream_context = upstream_call_args[0]

        # Verify the original envelope is forwarded upstream
        assert upstream_envelope is envelope

        # The upstream context should be the LOCAL context created for the response
        assert upstream_context.origin_type == DeliveryOriginType.LOCAL

    async def test_context_preservation_with_none_context(self, capability_handler, mock_routing_node):
        """Test that handler works correctly when context is None."""
        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.nocontext"],
            address=FameAddress("nocontext@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=generate_id())

        # Call the handler with None context
        await capability_handler.accept_capability_advertise(envelope, None)

        # Should return early due to no context
        mock_routing_node.forward_to_route.assert_not_called()

    async def test_security_context_attributes_preserved(self, capability_handler, mock_routing_node):
        """Test that all security context attributes are properly preserved."""
        # Create a rich security context
        rich_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(
                inbound_was_signed=True,
                inbound_crypto_level="sealed",
                crypto_channel_id="channel-123",
            ),
        )

        frame = CapabilityAdvertiseFrame(
            capabilities=["fame.capability.rich"],
            address=FameAddress("rich@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=generate_id())

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, rich_context)

        # Verify forward_to_route was called
        mock_routing_node.forward_to_route.assert_called_once()

        # Extract the response context
        call_args = mock_routing_node.forward_to_route.call_args
        segment, response_envelope, response_context = call_args[0]

        # Verify all security attributes are preserved
        assert response_context.security is not None
        assert response_context.security.inbound_was_signed is True
        assert response_context.security.inbound_crypto_level == "sealed"
        assert response_context.security.crypto_channel_id == "channel-123"

    async def test_multiple_capabilities_handled_correctly(
        self, capability_handler, mock_routing_node, signed_request_context
    ):
        """Test that multiple capabilities in one frame are handled correctly."""
        frame = CapabilityAdvertiseFrame(
            capabilities=[
                "fame.capability.multi1",
                "fame.capability.multi2",
                "fame.capability.multi3",
            ],
            address=FameAddress("multi@test-node-456.fame.fabric"),
        )
        envelope = create_fame_envelope(frame=frame, corr_id=generate_id())

        # Call the handler
        await capability_handler.accept_capability_advertise(envelope, signed_request_context)

        # Verify all capabilities were registered
        assert "fame.capability.multi1" in capability_handler._cap_routes
        assert "fame.capability.multi2" in capability_handler._cap_routes
        assert "fame.capability.multi3" in capability_handler._cap_routes

        # All should point to the same address and segment
        for cap in [
            "fame.capability.multi1",
            "fame.capability.multi2",
            "fame.capability.multi3",
        ]:
            routes = capability_handler._cap_routes[cap]
            assert FameAddress("multi@test-node-456.fame.fabric") in routes
            assert routes[FameAddress("multi@test-node-456.fame.fabric")] == "test-node-456"

        # Verify response was sent with LOCAL context
        mock_routing_node.forward_to_route.assert_called_once()
        call_args = mock_routing_node.forward_to_route.call_args
        segment, response_envelope, response_context = call_args[0]
        assert response_context.origin_type == DeliveryOriginType.LOCAL
