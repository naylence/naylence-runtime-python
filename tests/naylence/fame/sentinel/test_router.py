"""
Test coverage for the router module.

This module tests routing actions and state management for FAME message routing.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    EnvelopeFactory,
    FameDeliveryContext,
    FameEnvelope,
    FlowFlags,
    SecureAcceptFrame,
    SecureOpenFrame,
)
from naylence.fame.errors.errors import FameTransportClose
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Drop,
    ForwardChild,
    ForwardPeer,
    ForwardUp,
    RouterState,
    emit_delivery_nack,
    strip_self_prefix,
)


@pytest.fixture
def mock_router():
    """Create a mock RoutingNodeLike for testing."""
    router = AsyncMock(spec=RoutingNodeLike)
    return router


@pytest.fixture
def mock_envelope_factory():
    """Create a mock EnvelopeFactory for testing."""
    factory = MagicMock(spec=EnvelopeFactory)
    mock_envelope = MagicMock(spec=FameEnvelope)
    factory.create_envelope.return_value = mock_envelope
    return factory


@pytest.fixture
def router_state(mock_envelope_factory):
    """Create a basic RouterState for testing."""
    return RouterState(
        node_id="test-node",
        local={"local-addr"},
        downstream_address_routes={"child-addr": "child-segment"},
        peer_address_routes={"peer-addr": "peer-segment"},
        child_segments={"child-segment"},
        peer_segments={"peer-segment"},
        has_parent=True,
        physical_segments=["test-node"],
        pools={},
        envelope_factory=mock_envelope_factory,
    )


@pytest.fixture
def data_envelope():
    """Create a test DataFrame envelope."""
    frame = DataFrame(payload=b"test data")
    envelope = MagicMock(spec=FameEnvelope)
    envelope.frame = frame
    envelope.id = "test-id"
    envelope.reply_to = "reply-addr"
    envelope.corr_id = "corr-id"
    envelope.to = "dest-addr"
    envelope.sid = "test-sid"  # Add sid for logging
    envelope.trace_id = "test-trace-id"  # Add trace_id for logging
    return envelope


@pytest.fixture
def secure_open_envelope():
    """Create a test SecureOpenFrame envelope."""
    frame = SecureOpenFrame(
        cid="channel-id",
        eph_pub=b"0" * 32,  # 32-byte ephemeral key as required
        alg="test-alg",
    )
    envelope = MagicMock(spec=FameEnvelope)
    envelope.frame = frame
    envelope.id = "test-id"
    envelope.reply_to = "reply-addr"
    envelope.corr_id = "corr-id"
    envelope.to = "dest-addr"
    envelope.sid = "test-sid"  # Add sid for logging
    envelope.trace_id = "test-trace-id"  # Add trace_id for logging
    return envelope


@pytest.fixture
def delivery_ack_envelope():
    """Create a test DeliveryAckFrame envelope."""
    frame = DeliveryAckFrame(ok=True, code="OK", ref_id="ref-id")
    envelope = MagicMock(spec=FameEnvelope)
    envelope.frame = frame
    envelope.id = "test-id"
    envelope.reply_to = "reply-addr"
    envelope.corr_id = "corr-id"
    envelope.to = "dest-addr"
    envelope.sid = "test-sid"  # Add sid for logging
    envelope.trace_id = "test-trace-id"  # Add trace_id for logging
    return envelope


class TestEmitDeliveryNack:
    """Test the emit_delivery_nack function - lines 190-254."""

    async def test_emit_nack_for_data_frame_with_local_delivery(
        self, data_envelope, mock_router, router_state
    ):
        """Test NACK emission for DataFrame with local reply_to address."""
        data_envelope.reply_to = "local-addr"  # Address in state.local

        with patch("naylence.fame.sentinel.router.parse_address") as mock_parse:
            mock_parse.return_value = ("", "local-addr")

            await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should deliver locally
        mock_router.deliver_local.assert_called_once()
        args = mock_router.deliver_local.call_args[0]
        assert args[0] == "local-addr"  # target address

        # Check NACK envelope creation
        router_state.envelope_factory.create_envelope.assert_called_once()
        create_args = router_state.envelope_factory.create_envelope.call_args[1]
        assert create_args["to"] == "local-addr"
        assert create_args["flags"] == FlowFlags.RESET
        assert create_args["corr_id"] == "corr-id"

        # Verify NACK frame is DeliveryAckFrame
        nack_frame = create_args["frame"]
        assert isinstance(nack_frame, DeliveryAckFrame)
        assert not nack_frame.ok
        assert nack_frame.code == "NO_ROUTE"
        assert nack_frame.ref_id == "test-id"

    async def test_emit_nack_for_secure_open_frame(self, secure_open_envelope, mock_router, router_state):
        """Test NACK emission for SecureOpenFrame creates SecureAcceptFrame."""
        secure_open_envelope.reply_to = "local-addr"

        with patch("naylence.fame.sentinel.router.parse_address") as mock_parse:
            mock_parse.return_value = ("", "local-addr")

            await emit_delivery_nack(secure_open_envelope, mock_router, router_state, "NO_ROUTE")

        # Check NACK frame is SecureAcceptFrame
        create_args = router_state.envelope_factory.create_envelope.call_args[1]
        nack_frame = create_args["frame"]
        assert isinstance(nack_frame, SecureAcceptFrame)
        assert not nack_frame.ok
        assert nack_frame.ref_id == "test-id"
        assert nack_frame.cid == "channel-id"
        assert nack_frame.alg == "test-alg"
        assert "Channel handshake failed: NO_ROUTE" in nack_frame.reason

    async def test_emit_nack_forward_to_child_segment(self, data_envelope, mock_router, router_state):
        """Test NACK forwarding to child segment."""
        data_envelope.reply_to = "child-addr"

        with (
            patch("naylence.fame.sentinel.router.parse_address") as mock_parse,
            patch("naylence.fame.sentinel.router.strip_self_prefix") as mock_strip,
            patch("naylence.fame.sentinel.router.local_delivery_context") as mock_context,
        ):
            mock_parse.return_value = ("", "test-node/child-segment/target")
            mock_strip.return_value = ["child-segment", "target"]
            mock_context.return_value = MagicMock()

            await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should forward to child route
        mock_router.forward_to_route.assert_called_once()
        args = mock_router.forward_to_route.call_args[0]
        assert args[0] == "child-segment"

    async def test_emit_nack_forward_to_peer_segment(self, data_envelope, mock_router, router_state):
        """Test NACK forwarding to peer segment."""
        data_envelope.reply_to = "peer-addr"

        with (
            patch("naylence.fame.sentinel.router.parse_address") as mock_parse,
            patch("naylence.fame.sentinel.router.strip_self_prefix") as mock_strip,
            patch("naylence.fame.sentinel.router.local_delivery_context") as mock_context,
        ):
            mock_parse.return_value = ("", "test-node/peer-segment/target")
            mock_strip.return_value = ["peer-segment", "target"]
            mock_context.return_value = MagicMock()

            await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should forward to peer
        mock_router.forward_to_peer.assert_called_once()
        args = mock_router.forward_to_peer.call_args[0]
        assert args[0] == "peer-segment"

    async def test_emit_nack_forward_upstream_default(self, data_envelope, mock_router, router_state):
        """Test NACK forwarding upstream when no child/peer route found."""
        data_envelope.reply_to = "unknown-addr"

        with (
            patch("naylence.fame.sentinel.router.parse_address") as mock_parse,
            patch("naylence.fame.sentinel.router.strip_self_prefix") as mock_strip,
            patch("naylence.fame.sentinel.router.local_delivery_context") as mock_context,
        ):
            mock_parse.return_value = ("", "test-node/unknown-segment/target")
            mock_strip.return_value = ["unknown-segment", "target"]
            mock_context.return_value = MagicMock()

            await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should forward upstream as default
        mock_router.forward_upstream.assert_called_once()

    async def test_emit_nack_skip_when_no_reply_to(self, data_envelope, mock_router, router_state):
        """Test NACK emission skipped when envelope has no reply_to."""
        data_envelope.reply_to = None

        await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should not create any envelope or forward anything
        router_state.envelope_factory.create_envelope.assert_not_called()
        mock_router.deliver_local.assert_not_called()
        mock_router.forward_to_route.assert_not_called()
        mock_router.forward_upstream.assert_not_called()

    async def test_emit_nack_skip_when_no_envelope_id(self, data_envelope, mock_router, router_state):
        """Test NACK emission skipped when envelope has no id."""
        data_envelope.id = None

        await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should not create any envelope
        router_state.envelope_factory.create_envelope.assert_not_called()

    async def test_emit_nack_skip_when_no_corr_id(self, data_envelope, mock_router, router_state):
        """Test NACK emission skipped when envelope has no corr_id."""
        data_envelope.corr_id = None

        await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")

        # Should not create any envelope
        router_state.envelope_factory.create_envelope.assert_not_called()

    async def test_emit_nack_exception_handling(self, data_envelope, mock_router, router_state):
        """Test NACK emission handles exceptions gracefully."""
        data_envelope.reply_to = "local-addr"
        mock_router.deliver_local.side_effect = Exception("Test error")

        with patch("naylence.fame.sentinel.router.parse_address") as mock_parse:
            mock_parse.return_value = ("", "local-addr")

            # Should not raise exception
            await emit_delivery_nack(data_envelope, mock_router, router_state, "NO_ROUTE")


class TestDrop:
    """Test the Drop routing action - lines 64-66."""

    async def test_drop_calls_emit_delivery_nack(self, data_envelope, mock_router, router_state):
        """Test Drop action calls emit_delivery_nack with NO_ROUTE code."""
        action = Drop()

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await action.execute(data_envelope, mock_router, router_state)

            mock_emit.assert_called_once_with(
                data_envelope, mock_router, router_state, code="NO_ROUTE", context=None
            )

    async def test_drop_with_context(self, data_envelope, mock_router, router_state):
        """Test Drop action passes context to emit_delivery_nack."""
        action = Drop()
        context = MagicMock(spec=FameDeliveryContext)

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await action.execute(data_envelope, mock_router, router_state, context)

            mock_emit.assert_called_once_with(
                data_envelope, mock_router, router_state, code="NO_ROUTE", context=context
            )


class TestForwardUp:
    """Test the ForwardUp routing action - line 77."""

    async def test_forward_up_calls_forward_upstream(self, data_envelope, mock_router, router_state):
        """Test ForwardUp action calls router.forward_upstream."""
        action = ForwardUp()

        await action.execute(data_envelope, mock_router, router_state)

        mock_router.forward_upstream.assert_called_once_with(data_envelope, None)

    async def test_forward_up_with_context(self, data_envelope, mock_router, router_state):
        """Test ForwardUp action passes context to forward_upstream."""
        action = ForwardUp()
        context = MagicMock(spec=FameDeliveryContext)

        await action.execute(data_envelope, mock_router, router_state, context)

        mock_router.forward_upstream.assert_called_once_with(data_envelope, context)


class TestDeliverLocal:
    """Test the DeliverLocal routing action - line 91."""

    async def test_deliver_local_calls_deliver_local(self, data_envelope, mock_router, router_state):
        """Test DeliverLocal action calls router.deliver_local with recipient."""
        recipient = "test-recipient"
        action = DeliverLocal(recipient)

        await action.execute(data_envelope, mock_router, router_state)

        mock_router.deliver_local.assert_called_once_with(recipient, data_envelope, None)

    async def test_deliver_local_with_context(self, data_envelope, mock_router, router_state):
        """Test DeliverLocal action passes context to deliver_local."""
        recipient = "test-recipient"
        action = DeliverLocal(recipient)
        context = MagicMock(spec=FameDeliveryContext)

        await action.execute(data_envelope, mock_router, router_state, context)

        mock_router.deliver_local.assert_called_once_with(recipient, data_envelope, context)


class TestForwardChild:
    """Test the ForwardChild routing action - lines 105-111."""

    async def test_forward_child_successful(self, data_envelope, mock_router, router_state):
        """Test ForwardChild action successful forward."""
        segment = "test-segment"
        action = ForwardChild(segment)

        await action.execute(data_envelope, mock_router, router_state)

        mock_router.forward_to_route.assert_called_once_with(segment, data_envelope, None)

    async def test_forward_child_transport_close_with_data_frame(
        self, data_envelope, mock_router, router_state
    ):
        """Test ForwardChild handles FameTransportClose and emits NACK for non-DeliveryAckFrame."""
        segment = "test-segment"
        action = ForwardChild(segment)
        mock_router.forward_to_route.side_effect = FameTransportClose("Transport closed")

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await action.execute(data_envelope, mock_router, router_state)

        # Should remove downstream route
        mock_router.remove_downstream_route.assert_called_once_with(segment)

        # Should emit NACK for non-DeliveryAckFrame
        mock_emit.assert_called_once_with(
            envelope=data_envelope,
            routing_node=mock_router,
            state=router_state,
            code="ROUTE_CONNECTOR_CLOSED",
            context=None,
        )

    async def test_forward_child_transport_close_with_delivery_ack(
        self, delivery_ack_envelope, mock_router, router_state
    ):
        """Test ForwardChild handles FameTransportClose but no NACK for DeliveryAckFrame."""
        segment = "test-segment"
        action = ForwardChild(segment)
        mock_router.forward_to_route.side_effect = FameTransportClose("Transport closed")

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await action.execute(delivery_ack_envelope, mock_router, router_state)

        # Should remove downstream route
        mock_router.remove_downstream_route.assert_called_once_with(segment)

        # Should NOT emit NACK for DeliveryAckFrame
        mock_emit.assert_not_called()


class TestForwardPeer:
    """Test the ForwardPeer routing action - lines 131-137."""

    async def test_forward_peer_successful(self, data_envelope, mock_router, router_state):
        """Test ForwardPeer action successful forward."""
        segment = "test-segment"
        action = ForwardPeer(segment)

        await action.execute(data_envelope, mock_router, router_state)

        mock_router.forward_to_peer.assert_called_once_with(segment, data_envelope, None)

    async def test_forward_peer_transport_close_with_data_frame(
        self, data_envelope, mock_router, router_state
    ):
        """Test ForwardPeer handles FameTransportClose and emits NACK for non-DeliveryAckFrame."""
        segment = "test-segment"
        action = ForwardPeer(segment)
        mock_router.forward_to_peer.side_effect = FameTransportClose("Transport closed")

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await action.execute(data_envelope, mock_router, router_state)

        # Should remove peer route
        mock_router.remove_peer_route.assert_called_once_with(segment)

        # Should emit NACK for non-DeliveryAckFrame
        mock_emit.assert_called_once_with(
            envelope=data_envelope,
            routing_node=mock_router,
            state=router_state,
            code="ROUTE_CONNECTOR_CLOSED",
            context=None,
        )

    async def test_forward_peer_transport_close_with_delivery_ack(
        self, delivery_ack_envelope, mock_router, router_state
    ):
        """Test ForwardPeer handles FameTransportClose but no NACK for DeliveryAckFrame."""
        segment = "test-segment"
        action = ForwardPeer(segment)
        mock_router.forward_to_peer.side_effect = FameTransportClose("Transport closed")

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await action.execute(delivery_ack_envelope, mock_router, router_state)

        # Should remove peer route
        mock_router.remove_peer_route.assert_called_once_with(segment)

        # Should NOT emit NACK for DeliveryAckFrame
        mock_emit.assert_not_called()


class TestRouterState:
    """Test RouterState functionality - lines 179-180."""

    def test_next_hop_with_matching_prefix(self, router_state):
        """Test next_hop returns first segment after stripping self prefix."""
        router_state.physical_segments = ["R001", "C873"]

        result = router_state.next_hop("/R001/C873/next/target")

        assert result == "next"

    def test_next_hop_with_no_remainder(self, router_state):
        """Test next_hop returns None when path matches exactly."""
        router_state.physical_segments = ["R001"]

        result = router_state.next_hop("/R001")

        assert result is None

    def test_next_hop_with_empty_remainder(self, router_state):
        """Test next_hop returns None when remainder is empty."""
        router_state.physical_segments = ["R001"]

        with patch("naylence.fame.sentinel.router.strip_self_prefix") as mock_strip:
            mock_strip.return_value = []

            result = router_state.next_hop("/some/path")

            assert result is None


class TestStripSelfPrefix:
    """Test the strip_self_prefix utility function - lines 262-265."""

    def test_strip_matching_prefix(self):
        """Test stripping when path starts with self segments."""
        result = strip_self_prefix("/R001/C873/abc", ["R001"])
        assert result == ["C873", "abc"]

    def test_strip_exact_match(self):
        """Test stripping when path exactly matches self segments."""
        result = strip_self_prefix("/R001", ["R001"])
        assert result == []

    def test_strip_multi_segment_prefix(self):
        """Test stripping multiple self segments."""
        result = strip_self_prefix("/R001/C873/abc/def", ["R001", "C873"])
        assert result == ["abc", "def"]

    def test_strip_no_match(self):
        """Test no stripping when path doesn't start with self segments."""
        result = strip_self_prefix("/OTHER/C873/abc", ["R001"])
        assert result == ["OTHER", "C873", "abc"]
