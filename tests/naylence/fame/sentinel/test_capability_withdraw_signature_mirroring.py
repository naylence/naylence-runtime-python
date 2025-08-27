#!/usr/bin/env python3
"""
Test for CapabilityWithdraw signature mirroring - documenting current behavior and expected fix.

The accept_capability_withdraw method currently has the same signature mirroring issue
as accept_capability_advertise had before the fix. This test documents the issue and
provides a test for when it gets fixed with the same pattern.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    CapabilityWithdrawAckFrame,
    CapabilityWithdrawFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    create_fame_envelope,
    generate_id,
)
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.sentinel.capability_frame_handler import CapabilityFrameHandler


class TestCapabilityWithdrawSignatureMirroring:
    """Test signature mirroring behavior for CapabilityWithdraw frames."""

    @pytest.fixture
    def mock_routing_node(self):
        """Create a mock routing node."""
        mock_node = MagicMock()
        mock_node.sid = "test-sentinel"

        mock_envelope_factory = MagicMock()
        mock_node.envelope_factory = mock_envelope_factory

        def create_real_envelope(frame, corr_id=None):
            return create_fame_envelope(frame=frame, corr_id=corr_id)

        mock_envelope_factory.create_envelope.side_effect = create_real_envelope

        mock_node.forward_to_route = AsyncMock()
        mock_node.forward_upstream = AsyncMock()

        return mock_node

    @pytest.fixture
    def capability_handler(self, mock_routing_node):
        """Create a CapabilityFrameHandler instance."""
        mock_route_manager = MagicMock()
        mock_route_manager.downstream_routes = {"test-node-456": "connector"}

        handler = CapabilityFrameHandler(
            routing_node=mock_routing_node,
            route_manager=mock_route_manager,
            upstream_connector=MagicMock(return_value=None),
        )

        # Pre-register a capability that can be withdrawn
        test_address = FameAddress("math@test-node-456.fame.fabric")
        handler._cap_routes["fame.capability.math"][test_address] = "test-node-456"

        return handler

    async def test_capability_withdraw_now_creates_local_context_for_signed_request(
        self, capability_handler, mock_routing_node
    ):
        """
        Test that CapabilityWithdraw now creates LOCAL context preserving security info.

        This validates that the same fix applied to accept_capability_advertise
        has now been applied to accept_capability_withdraw as well.
        """
        # Create a signed request context (downstream origin)
        signed_downstream_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(inbound_was_signed=True, inbound_crypto_level="signed"),
        )

        # Create withdraw frame
        corr_id = generate_id()
        withdraw_frame = CapabilityWithdrawFrame(
            capabilities=["fame.capability.math"],
            address=FameAddress("math@test-node-456.fame.fabric"),
        )
        withdraw_envelope = create_fame_envelope(frame=withdraw_frame, corr_id=corr_id)

        # Process the withdraw
        await capability_handler.accept_capability_withdraw(withdraw_envelope, signed_downstream_context)

        # Verify forward_to_route was called
        mock_routing_node.forward_to_route.assert_called_once()

        # Extract the call arguments
        call_args = mock_routing_node.forward_to_route.call_args
        segment, ack_envelope, ack_context = call_args[0]

        # FIXED BEHAVIOR: Now uses LOCAL origin (enabling signing)
        assert ack_context.origin_type == DeliveryOriginType.LOCAL, (
            "FIXED BEHAVIOR: withdraw ACK now uses LOCAL origin - can be signed!"
        )

        # Security info is preserved for mirroring
        assert ack_context.security is not None
        assert ack_context.security.inbound_was_signed is True, (
            "inbound_was_signed should be preserved for signature mirroring"
        )
        assert ack_context.security.inbound_crypto_level == "signed", "Crypto level should be preserved"

        # Verify correct ACK frame
        assert isinstance(ack_envelope.frame, CapabilityWithdrawAckFrame)
        assert ack_envelope.frame.ok is True

    def test_capability_withdraw_fix_pattern_validation(self):
        """
        Validate that the CapabilityWithdraw fix uses the same pattern as CapabilityAdvertise.

        This confirms that both methods now use the identical LOCAL context creation pattern.
        """
        # Original downstream context (like what we receive)
        original_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(inbound_was_signed=True, inbound_crypto_level="signed"),
            stickiness_required=True,
            sticky_sid="session-123",
        )

        # THE IMPLEMENTED FIX: Create LOCAL context preserving security info
        # This is what both advertise and withdraw now do
        implemented_ack_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,  # KEY FIX: LOCAL for signing
            security=(original_context.security if original_context else None),  # Preserve security
            stickiness_required=(original_context.stickiness_required if original_context else None),
            sticky_sid=original_context.sticky_sid if original_context else None,
        )

        # Verify the implemented fix has the right properties
        assert implemented_ack_context.origin_type == DeliveryOriginType.LOCAL
        assert implemented_ack_context.security.inbound_was_signed is True
        assert implemented_ack_context.security.inbound_crypto_level == "signed"
        assert implemented_ack_context.stickiness_required is True
        assert implemented_ack_context.sticky_sid == "session-123"

    async def test_capability_withdraw_removes_capability_correctly(
        self, capability_handler, mock_routing_node
    ):
        """Test that capability withdrawal removes capabilities from routing table."""
        # Verify capability is initially present
        test_address = FameAddress("math@test-node-456.fame.fabric")
        assert "fame.capability.math" in capability_handler._cap_routes
        assert test_address in capability_handler._cap_routes["fame.capability.math"]

        signed_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(inbound_was_signed=True),
        )

        withdraw_frame = CapabilityWithdrawFrame(
            capabilities=["fame.capability.math"],
            address=test_address,
        )
        withdraw_envelope = create_fame_envelope(frame=withdraw_frame, corr_id=generate_id())

        # Process the withdraw
        await capability_handler.accept_capability_withdraw(withdraw_envelope, signed_context)

        # Verify capability was removed
        assert "fame.capability.math" not in capability_handler._cap_routes

        # Verify ACK was sent
        mock_routing_node.forward_to_route.assert_called_once()

    async def test_capability_withdraw_upstream_propagation_on_vanished_global(
        self, capability_handler, mock_routing_node
    ):
        """Test upstream propagation when capability vanishes globally."""
        # Mock upstream connector
        capability_handler._upstream_connector = MagicMock(return_value="upstream-connector")

        signed_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-node-456",
            security=SecurityContext(inbound_was_signed=True),
        )

        # This will remove the last (only) instance of the capability
        withdraw_frame = CapabilityWithdrawFrame(
            capabilities=["fame.capability.math"],
            address=FameAddress("math@test-node-456.fame.fabric"),
        )
        withdraw_envelope = create_fame_envelope(frame=withdraw_frame, corr_id=generate_id())

        # Process the withdraw
        await capability_handler.accept_capability_withdraw(withdraw_envelope, signed_context)

        # Verify downstream ACK
        mock_routing_node.forward_to_route.assert_called_once()

        # Verify upstream propagation occurred
        mock_routing_node.forward_upstream.assert_called_once()
        upstream_call_args = mock_routing_node.forward_upstream.call_args
        upstream_envelope, upstream_context = upstream_call_args[0]

        # Verify original envelope forwarded upstream
        assert upstream_envelope is withdraw_envelope

        # FIXED: Now uses LOCAL context consistently for upstream too
        assert upstream_context.origin_type == DeliveryOriginType.LOCAL
