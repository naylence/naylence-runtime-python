#!/usr/bin/env python3
"""
Comprehensive test suite for Sentinel to improve coverage to 85%+.

This test file focuses on covering the specific lines and edge cases
that are currently missing from the existing test coverage.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import (
    AddressBindFrame,
    AddressUnbindFrame,
    AuthorizationContext,
    CapabilityAdvertiseFrame,
    CapabilityWithdrawFrame,
    CreditUpdateFrame,
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FlowFlags,
    NodeAttachFrame,
    NodeHeartbeatFrame,
    create_fame_envelope,
    local_delivery_context,
)
from naylence.fame.node.admission.node_attach_client import AttachInfo
from naylence.fame.sentinel.peer import Peer
from naylence.fame.sentinel.sentinel import DEFAULT_ATTACH_TIMEOUT_SEC, Sentinel
from naylence.fame.sentinel.store.route_store import RouteStore


class TestSentinelComprehensive:
    """Comprehensive test suite for Sentinel covering missing lines."""

    @pytest.fixture
    def mock_security_manager(self):
        """Create a mock security manager with all required components."""
        security_manager = MagicMock()
        security_manager.authorizer = MagicMock()
        security_manager.key_manager = MagicMock()
        # Add all the event listener methods as AsyncMocks
        security_manager.on_node_initialized = AsyncMock()
        security_manager.on_node_started = AsyncMock()
        security_manager.on_node_stopped = AsyncMock()
        security_manager.on_welcome = AsyncMock()
        return security_manager

    @pytest.fixture
    def mock_route_store(self):
        """Create a mock route store."""
        store = MagicMock(spec=RouteStore)
        store.get_all_routes = AsyncMock(return_value=[])
        store.store_route = AsyncMock()
        store.remove_route = AsyncMock()
        store.list = AsyncMock(return_value={})  # Return empty dict for route entries
        return store

    @pytest.fixture
    def mock_connector_config(self):
        """Create a mock connector config."""
        config = MagicMock(spec=ConnectorConfig)
        config.type = "test"
        return config

    @pytest.fixture
    def mock_connector(self):
        """Create a mock connector."""
        connector = MagicMock(spec=FameConnector)
        connector.start = AsyncMock()
        connector.send = AsyncMock()
        connector.stop = AsyncMock()
        connector.system_id = "test-connector"
        return connector

    @pytest.fixture
    def mock_attach_client(self):
        """Create a mock attach client."""
        client = MagicMock()
        client.attach = AsyncMock()
        return client

    @pytest.fixture
    def mock_admission_client(self):
        """Create a mock admission client."""
        client = MagicMock()
        client.create_origin_connector = AsyncMock()
        return client

    @pytest.fixture
    def sentinel(self, mock_security_manager, mock_route_store):
        """Create a Sentinel instance for testing."""
        return Sentinel(
            has_parent=False,
            security_manager=mock_security_manager,
            route_store=mock_route_store,
            attach_timeout_sec=DEFAULT_ATTACH_TIMEOUT_SEC,
            binding_ack_timeout_ms=5000,
        )

    async def test_sentinel_initialization_error_no_authorizer(self, mock_route_store):
        """Test Sentinel initialization fails when no authorizer is provided."""
        # Create security manager without authorizer
        security_manager = MagicMock()
        security_manager.authorizer = None

        # Should fail on AssertionError (the assert comes before the if check)
        with pytest.raises(AssertionError):
            Sentinel(
                has_parent=False,
                security_manager=security_manager,
                route_store=mock_route_store,
            )

    async def test_sentinel_properties(self, sentinel):
        """Test Sentinel properties."""
        # Test routing_epoch property
        assert sentinel.routing_epoch is not None
        assert isinstance(sentinel.routing_epoch, str)

        # Test security_manager property
        assert sentinel.security_manager is not None
        assert sentinel.security_manager == sentinel._security_manager

    async def test_sentinel_lifecycle_with_peers(
        self,
        mock_security_manager,
        mock_route_store,
        mock_attach_client,
        mock_admission_client,
    ):
        """Test Sentinel lifecycle with peers."""
        # Create peer
        peer = Peer(
            admission_client=mock_admission_client,
        )

        # Create sentinel with peers
        sentinel = Sentinel(
            has_parent=False,
            security_manager=mock_security_manager,
            route_store=mock_route_store,
            peers=[peer],
        )
        sentinel.attach_client = mock_attach_client

        # Mock peer session manager
        mock_session_manager = MagicMock()
        mock_session_manager.start = AsyncMock()
        mock_session_manager.system_id = "test-peer-session"

        with patch(
            "naylence.fame.sentinel.sentinel.UpstreamSessionManager",
            return_value=mock_session_manager,
        ):
            await sentinel.start()

        # Verify security manager was notified (should be called once now that bug is fixed)
        mock_security_manager.on_node_initialized.assert_called_once_with(sentinel)

        # Verify peer connection was attempted
        assert mock_session_manager.start.called

        await sentinel.stop()

    async def test_maybe_forget_flow(self, sentinel):
        """Test _maybe_forget_flow method."""
        # Create envelope with flow_id
        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        envelope.flow_id = "test-flow-id"

        # Set up flow route
        sentinel._route_manager._flow_routes["test-flow-id"] = MagicMock()

        # Test without RESET flag - should not remove flow
        envelope.flow_flags = None
        sentinel._maybe_forget_flow(envelope)
        assert "test-flow-id" in sentinel._route_manager._flow_routes

        # Test with RESET flag - should remove flow
        envelope.flow_flags = FlowFlags.RESET
        sentinel._maybe_forget_flow(envelope)
        assert "test-flow-id" not in sentinel._route_manager._flow_routes

        # Test without flow_id - should not crash
        envelope.flow_id = None
        sentinel._maybe_forget_flow(envelope)  # Should not raise

    async def test_create_origin_connector(self, sentinel, mock_connector_config):
        """Test create_origin_connector method."""
        mock_connector = MagicMock(spec=FameConnector)
        mock_connector.start = AsyncMock()

        with patch(
            "naylence.fame.sentinel.sentinel.create_resource",
            return_value=mock_connector,
        ):
            connector = await sentinel.create_origin_connector(
                origin_type=DeliveryOriginType.DOWNSTREAM,
                system_id="test-system",
                connector_config=mock_connector_config,
                websocket="test-primitive",
                authorization=AuthorizationContext(),
            )

            assert connector == mock_connector
            mock_connector.start.assert_called_once()

    async def test_create_origin_connector_gated_handler(self, sentinel, mock_connector_config):
        """Test the gated handler in create_origin_connector."""
        mock_connector = MagicMock(spec=FameConnector)
        mock_connector.start = AsyncMock()

        # Capture the handler that gets passed to connector.start
        captured_handler = None

        async def capture_start(handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_connector.start = capture_start

        with patch(
            "naylence.fame.sentinel.sentinel.create_resource",
            return_value=mock_connector,
        ):
            await sentinel.create_origin_connector(
                origin_type=DeliveryOriginType.DOWNSTREAM,
                system_id="test-system",
                connector_config=mock_connector_config,
            )

            # Test the gated handler
            assert captured_handler is not None

            # Test handler with NodeAttach frame (allowed before attach)
            attach_frame = NodeAttachFrame(
                system_id="test-system",
                instance_id="test-instance",
                assigned_path="/test",
                capabilities=[],
            )
            attach_envelope = create_fame_envelope(frame=attach_frame)

            # Mock deliver method
            sentinel.deliver = AsyncMock()

            # Should call deliver for NodeAttach frame
            await captured_handler(attach_envelope)
            sentinel.deliver.assert_called_once()

    async def test_create_origin_connector_gated_handler_buffering(self, sentinel, mock_connector_config):
        """Test the gated handler buffering mechanism."""
        mock_connector = MagicMock(spec=FameConnector)

        # Capture the handler
        captured_handler = None
        attached_event = None

        async def capture_start(handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_connector.start = capture_start

        with patch(
            "naylence.fame.sentinel.sentinel.create_resource",
            return_value=mock_connector,
        ):
            await sentinel.create_origin_connector(
                origin_type=DeliveryOriginType.DOWNSTREAM,
                system_id="test-system",
                connector_config=mock_connector_config,
            )

            # Get the attached event
            pending_info = sentinel._route_manager._pending_routes.get("test-system")
            assert pending_info is not None
            attached_event = pending_info[1]  # (connector, attached, buffer)

            # Test handler with non-NodeAttach frame (should be buffered)
            data_frame = DataFrame(payload={"test": "data"}, codec="json")
            data_envelope = create_fame_envelope(frame=data_frame)

            sentinel.deliver = AsyncMock()

            # Should buffer the frame since not attached
            await captured_handler(data_envelope)

            # Deliver should not be called yet
            sentinel.deliver.assert_not_called()

            # Verify frame is buffered
            buffer = pending_info[2]
            assert len(buffer) == 1
            assert buffer[0] == data_envelope

            # Now set attached and send another frame
            attached_event.set()

            heartbeat_frame = NodeHeartbeatFrame()
            heartbeat_envelope = create_fame_envelope(frame=heartbeat_frame)

            await captured_handler(heartbeat_envelope)

            # Should deliver buffered frame and new frame
            assert sentinel.deliver.call_count == 2

    async def test_child_for(self, sentinel):
        """Test child_for method."""
        # Set up route info
        addr = FameAddress("service@/test/addr")
        route_info = MagicMock()
        route_info.segment = "test-segment"
        sentinel._route_manager._downstream_addresses_routes[addr] = route_info

        # Test existing address
        child = sentinel.child_for(addr)
        assert child == "test-segment"

        # Test non-existing address
        unknown_addr = FameAddress("service@/unknown")
        child = sentinel.child_for(unknown_addr)
        assert child is None

    async def test_build_router_state(self, sentinel):
        """Test build_router_state method."""
        # Set up some test data
        sentinel._binding_manager = MagicMock()
        sentinel._binding_manager.get_addresses.return_value = [FameAddress("service@/test")]

        # Set up route manager data
        test_addr = FameAddress("service@/test")
        route_info = MagicMock()
        route_info.segment = "test-segment"
        sentinel._route_manager._downstream_addresses_routes[test_addr] = route_info
        sentinel._route_manager._peer_addresses_routes[test_addr] = "peer-segment"
        sentinel._route_manager.downstream_routes["test-segment"] = MagicMock()
        sentinel._route_manager._peer_routes["peer-segment"] = MagicMock()

        # Set up other components
        sentinel._address_bind_frame_handler = MagicMock()
        sentinel._address_bind_frame_handler.pools = {}
        sentinel._capability_frame_handler = MagicMock()
        sentinel._capability_frame_handler.cap_routes = {}
        sentinel._service_manager = MagicMock()
        sentinel._service_manager.resolve_address_by_capability = MagicMock()
        sentinel._envelope_factory = MagicMock()

        router_state = sentinel.build_router_state()

        assert router_state.node_id == sentinel.id
        assert test_addr in router_state.local
        assert test_addr in router_state.downstream_address_routes
        assert router_state.downstream_address_routes[test_addr] == "test-segment"

    async def test_is_attached(self, sentinel):
        """Test _is_attached method."""
        # Test non-attached segment
        assert not sentinel._is_attached("non-existent")

        # Add a route
        mock_connector = MagicMock()
        sentinel._route_manager.downstream_routes["test-segment"] = mock_connector

        # Test attached segment
        assert sentinel._is_attached("test-segment")

    async def test_downstream_connector(self, sentinel):
        """Test _downstream_connector method."""
        # Test non-existent connector
        assert sentinel._downstream_connector("non-existent") is None

        # Add a connector
        mock_connector = MagicMock()
        sentinel._route_manager.downstream_routes["test-segment"] = mock_connector

        # Test existing connector
        assert sentinel._downstream_connector("test-segment") == mock_connector

    async def test_on_epoch_change(self, sentinel):
        """Test _on_epoch_change method."""
        # Mock super()._on_epoch_change
        with patch.object(
            type(sentinel).__bases__[0], "_on_epoch_change", new_callable=AsyncMock
        ) as mock_super:
            # Mock _propagate_address_bindings_upstream
            sentinel._propagate_address_bindings_upstream = AsyncMock()

            await sentinel._on_epoch_change("new-epoch")

            mock_super.assert_called_once_with("new-epoch")
            sentinel._propagate_address_bindings_upstream.assert_called_once_with("new-epoch")

    async def test_propagate_address_bindings_upstream_no_parent(self, sentinel):
        """Test _propagate_address_bindings_upstream when no parent."""
        # Sentinel has no parent by default
        assert not sentinel.has_parent

        with patch("naylence.fame.sentinel.sentinel.logger") as mock_logger:
            await sentinel._propagate_address_bindings_upstream("test-epoch")
            mock_logger.warning.assert_called_once_with("No upstream defined to rebind addresses")

    async def test_propagate_address_bindings_upstream_with_parent(
        self, mock_security_manager, mock_route_store
    ):
        """Test _propagate_address_bindings_upstream with parent."""
        # Create sentinel with parent
        sentinel = Sentinel(
            has_parent=True,
            security_manager=mock_security_manager,
            route_store=mock_route_store,
        )

        # Set up test routes
        test_addr = FameAddress("service@/test")
        route_info = MagicMock()
        route_info.physical_path = "/test/path"
        route_info.encryption_key_id = "test-key"
        sentinel._route_manager._downstream_addresses_routes[test_addr] = route_info

        # Mock _bind_address_upstream
        sentinel._bind_address_upstream = AsyncMock()

        await sentinel._propagate_address_bindings_upstream("test-epoch")

        # Should call _bind_address_upstream for each route
        sentinel._bind_address_upstream.assert_called_once_with(test_addr, route_info)

    async def test_bind_address_upstream(self, mock_security_manager, mock_route_store):
        """Test _bind_address_upstream method."""
        # Create sentinel with parent
        sentinel = Sentinel(
            has_parent=True,
            security_manager=mock_security_manager,
            route_store=mock_route_store,
        )

        # Set up required attributes
        sentinel._pending_binds = {}
        sentinel._pending_lock = asyncio.Lock()
        sentinel._ack_timeout_sec = 1.0
        sentinel._envelope_factory = MagicMock()
        sentinel._envelope_factory.create_envelope.return_value = create_fame_envelope(
            frame=NodeHeartbeatFrame()
        )
        sentinel.forward_upstream = AsyncMock()
        sentinel._physical_path = "/test/sentinel"

        # Create route info
        test_addr = FameAddress("service@/test")
        route_info = MagicMock()
        route_info.physical_path = "/test/path"
        route_info.encryption_key_id = "test-key"

        # Test successful bind
        async def mock_wait_for(fut, timeout):
            # Simulate successful ACK
            fut.set_result(True)
            return True

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            await sentinel._bind_address_upstream(test_addr, route_info)
            sentinel.forward_upstream.assert_called_once()

    async def test_bind_address_upstream_timeout(self, mock_security_manager, mock_route_store):
        """Test _bind_address_upstream timeout."""
        # Create sentinel with parent
        sentinel = Sentinel(
            has_parent=True,
            security_manager=mock_security_manager,
            route_store=mock_route_store,
        )

        # Set up required attributes
        sentinel._pending_binds = {}
        sentinel._pending_lock = asyncio.Lock()
        sentinel._ack_timeout_sec = 0.1  # Short timeout
        sentinel._envelope_factory = MagicMock()
        sentinel._envelope_factory.create_envelope.return_value = create_fame_envelope(
            frame=NodeHeartbeatFrame()
        )
        sentinel.forward_upstream = AsyncMock()
        sentinel._physical_path = "/test/sentinel"

        # Create route info
        test_addr = FameAddress("service@/test")
        route_info = MagicMock()
        route_info.physical_path = "/test/path"
        route_info.encryption_key_id = "test-key"

        # Test timeout
        with pytest.raises(RuntimeError, match="Timeout waiting for bind ack"):
            await sentinel._bind_address_upstream(test_addr, route_info)

    async def test_bind_address_upstream_rejected(self, mock_security_manager, mock_route_store):
        """Test _bind_address_upstream rejection."""
        # Create sentinel with parent
        sentinel = Sentinel(
            has_parent=True,
            security_manager=mock_security_manager,
            route_store=mock_route_store,
        )

        # Set up required attributes
        sentinel._pending_binds = {}
        sentinel._pending_lock = asyncio.Lock()
        sentinel._ack_timeout_sec = 1.0
        sentinel._envelope_factory = MagicMock()
        sentinel._envelope_factory.create_envelope.return_value = create_fame_envelope(
            frame=NodeHeartbeatFrame()
        )
        sentinel.forward_upstream = AsyncMock()
        sentinel._physical_path = "/test/sentinel"

        # Create route info
        test_addr = FameAddress("service@/test")
        route_info = MagicMock()
        route_info.physical_path = "/test/path"
        route_info.encryption_key_id = "test-key"

        # Test rejection
        async def mock_wait_for(fut, timeout):
            # Simulate rejection
            fut.set_result(False)
            return False

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            with pytest.raises(RuntimeError, match="was rejected"):
                await sentinel._bind_address_upstream(test_addr, route_info)

    async def test_deliver_frame_types(self, sentinel):
        """Test deliver method with different frame types."""
        # Mock handlers
        sentinel._node_attach_frame_handler.accept_node_attach = AsyncMock()
        sentinel._address_bind_frame_handler.accept_address_bind = AsyncMock()
        sentinel._address_bind_frame_handler.accept_address_unbind = AsyncMock()
        sentinel._capability_frame_handler.accept_capability_advertise = AsyncMock()
        sentinel._capability_frame_handler.accept_capability_withdraw = AsyncMock()
        sentinel._credit_update_frame_handler.accept_credit_update = AsyncMock()
        sentinel._node_heartbeat_frame_handler.accept_node_heartbeat = AsyncMock()

        # Mock routing policy
        mock_action = MagicMock()
        mock_action.execute = AsyncMock()
        sentinel._routing_policy.decide = AsyncMock(return_value=mock_action)

        # Mock build_router_state
        sentinel.build_router_state = MagicMock(return_value=MagicMock())

        # Mock dispatch_envelope_event to return the envelope unchanged
        # Simulate the real behavior which finds the envelope by checking for .frame attribute
        def mock_dispatch_envelope_event(event, *args, **kwargs):
            # Find the envelope in the arguments - look for object with .frame attribute
            if "envelope" in kwargs:
                return kwargs["envelope"]
            for arg in args:
                if hasattr(arg, "frame"):
                    return arg
            return args[0] if args else None
        
        sentinel._dispatch_envelope_event = AsyncMock(side_effect=mock_dispatch_envelope_event)

        # Test different frame types
        test_cases = [
            (
                NodeAttachFrame(
                    system_id="test",
                    instance_id="test",
                    assigned_path="/test",
                    capabilities=[],
                ),
                "accept_node_attach",
            ),
            (
                AddressBindFrame(
                    address=FameAddress("test@/test"),
                    encryption_key_id="key",
                    corr_id="corr",
                ),
                "accept_address_bind",
            ),
            (
                AddressUnbindFrame(address=FameAddress("test@/test"), corr_id="corr"),
                "accept_address_unbind",
            ),
            (
                CapabilityAdvertiseFrame(capabilities=["test-cap"], address=FameAddress("test@/test")),
                "accept_capability_advertise",
            ),
            (
                CapabilityWithdrawFrame(capabilities=["test-cap"], address=FameAddress("test@/test")),
                "accept_capability_withdraw",
            ),
            (
                CreditUpdateFrame(flow_id="test-flow", credits=100),
                "accept_credit_update",
            ),
            (NodeHeartbeatFrame(), "accept_node_heartbeat"),
        ]

        for frame, expected_handler in test_cases:
            envelope = create_fame_envelope(frame=frame)
            # Use None context so frame handlers are processed
            # (the new restriction only allows frame processing for non-LOCAL origins)
            context = None

            await sentinel.deliver(envelope, context)

            # Verify the appropriate handler was called
            if expected_handler == "accept_node_attach":
                sentinel._node_attach_frame_handler.accept_node_attach.assert_called()
            elif expected_handler == "accept_address_bind":
                sentinel._address_bind_frame_handler.accept_address_bind.assert_called()
            elif expected_handler == "accept_address_unbind":
                sentinel._address_bind_frame_handler.accept_address_unbind.assert_called()
            elif expected_handler == "accept_capability_advertise":
                sentinel._capability_frame_handler.accept_capability_advertise.assert_called()
            elif expected_handler == "accept_capability_withdraw":
                sentinel._capability_frame_handler.accept_capability_withdraw.assert_called()
            elif expected_handler == "accept_credit_update":
                sentinel._credit_update_frame_handler.accept_credit_update.assert_called()
            elif expected_handler == "accept_node_heartbeat":
                sentinel._node_heartbeat_frame_handler.accept_node_heartbeat.assert_called()

            # Verify routing action was executed
            mock_action.execute.assert_called()

            # Reset mocks for next iteration
            for handler in [
                sentinel._node_attach_frame_handler,
                sentinel._address_bind_frame_handler,
                sentinel._capability_frame_handler,
                sentinel._credit_update_frame_handler,
                sentinel._node_heartbeat_frame_handler,
            ]:
                for method in dir(handler):
                    if method.startswith("accept_"):
                        getattr(handler, method).reset_mock()
            mock_action.execute.reset_mock()

    async def test_deliver_security_processing_halt(self, sentinel):
        """Test deliver method when security processing halts delivery."""
        # Mock dispatch_envelope_event to return None (halt delivery)
        sentinel._dispatch_envelope_event = AsyncMock(return_value=None)

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        # Mock handlers to verify they're not called
        sentinel._node_heartbeat_frame_handler.accept_node_heartbeat = AsyncMock()
        sentinel._routing_policy.decide = AsyncMock()

        await sentinel.deliver(envelope, context)

        # Verify handlers were not called
        sentinel._node_heartbeat_frame_handler.accept_node_heartbeat.assert_not_called()
        sentinel._routing_policy.decide.assert_not_called()

    async def test_forward_to_route_no_route(self, sentinel):
        """Test forward_to_route when route doesn't exist."""
        # Mock dispatch_envelope_event to return the envelope unchanged
        sentinel._dispatch_envelope_event = AsyncMock(
            side_effect=lambda event, *args, **kwargs: (args[2] if len(args) > 2 else args[1])
        )

        # Mock emit_delivery_nack
        sentinel.emit_delivery_nack = AsyncMock()

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        await sentinel.forward_to_route("non-existent-segment", envelope, context)

        # Should emit NACK
        sentinel.emit_delivery_nack.assert_called_once_with(
            envelope, code="CHILD_UNREACHABLE", context=context
        )

    async def test_forward_to_route_with_flow(self, sentinel):
        """Test forward_to_route with flow tracking."""
        # Mock dispatch_envelope_event to return the envelope unchanged
        sentinel._dispatch_envelope_event = AsyncMock(
            side_effect=lambda event, *args, **kwargs: (args[2] if len(args) > 2 else args[1])
        )

        # Set up route
        mock_connector = MagicMock()
        mock_connector.send = AsyncMock()
        sentinel._route_manager.downstream_routes["test-segment"] = mock_connector

        # Create envelope with flow_id
        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        envelope.flow_id = "test-flow"
        envelope.flow_flags = FlowFlags.RESET
        context = local_delivery_context()

        await sentinel.forward_to_route("test-segment", envelope, context)

        # Verify connector.send was called
        mock_connector.send.assert_called_once_with(envelope)

        # Verify flow was tracked and then forgotten
        assert "test-flow" not in sentinel._route_manager._flow_routes

    async def test_forward_to_peer_no_route(self, sentinel):
        """Test forward_to_peer when peer route doesn't exist."""
        # Mock dispatch_envelope_event to return the envelope unchanged
        sentinel._dispatch_envelope_event = AsyncMock(
            side_effect=lambda event, *args, **kwargs: (args[2] if len(args) > 2 else args[1])
        )

        # Mock emit_delivery_nack
        sentinel.emit_delivery_nack = AsyncMock()

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        await sentinel.forward_to_peer("non-existent-peer", envelope, context)

        # Should emit NACK
        sentinel.emit_delivery_nack.assert_called_once_with(
            envelope, code="PEER_UNREACHABLE", context=context
        )

    async def test_forward_to_peer_with_flow(self, sentinel):
        """Test forward_to_peer with flow tracking."""
        # Mock dispatch_envelope_event to return the envelope unchanged
        sentinel._dispatch_envelope_event = AsyncMock(
            side_effect=lambda event, *args, **kwargs: (args[2] if len(args) > 2 else args[1])
        )

        # Set up peer route
        mock_connector = MagicMock()
        mock_connector.send = AsyncMock()
        sentinel._route_manager._peer_routes["test-peer"] = mock_connector

        # Create envelope with flow_id
        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        envelope.flow_id = "test-flow"
        context = local_delivery_context()

        await sentinel.forward_to_peer("test-peer", envelope, context)

        # Verify connector.send was called
        mock_connector.send.assert_called_once_with(envelope)

        # Verify flow was tracked
        assert sentinel._route_manager._flow_routes["test-flow"] == mock_connector

    async def test_forward_to_peers_all(self, sentinel):
        """Test forward_to_peers to all peers."""

        # Mock dispatch_envelope_event to return the envelope unchanged
        # Simulate the real behavior which finds the envelope by checking for .frame attribute
        def mock_dispatch_envelope_event(event, *args, **kwargs):
            # Find the envelope in the arguments - look for object with .frame attribute
            if "envelope" in kwargs:
                return kwargs["envelope"]
            for arg in args:
                if hasattr(arg, "frame"):
                    return arg
            return args[0] if args else None

        sentinel._dispatch_envelope_event = AsyncMock(side_effect=mock_dispatch_envelope_event)

        # Set up peer routes
        mock_connector1 = MagicMock()
        mock_connector1.send = AsyncMock()
        mock_connector2 = MagicMock()
        mock_connector2.send = AsyncMock()

        sentinel._route_manager._peer_routes["peer1"] = mock_connector1
        sentinel._route_manager._peer_routes["peer2"] = mock_connector2

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        await sentinel.forward_to_peers(envelope, context=context)

        # Both connectors should receive the envelope
        mock_connector1.send.assert_called_once_with(envelope)
        mock_connector2.send.assert_called_once_with(envelope)

    async def test_forward_to_peers_with_exclusions(self, sentinel):
        """Test forward_to_peers with exclusions."""

        # Mock dispatch_envelope_event to return the envelope unchanged
        # Simulate the real behavior which finds the envelope by checking for .frame attribute
        def mock_dispatch_envelope_event(event, *args, **kwargs):
            # Find the envelope in the arguments - look for object with .frame attribute
            if "envelope" in kwargs:
                return kwargs["envelope"]
            for arg in args:
                if hasattr(arg, "frame"):
                    return arg
            return args[0] if args else None

        sentinel._dispatch_envelope_event = AsyncMock(side_effect=mock_dispatch_envelope_event)

        # Set up peer routes
        mock_connector1 = MagicMock()
        mock_connector1.send = AsyncMock()
        mock_connector2 = MagicMock()
        mock_connector2.send = AsyncMock()

        sentinel._route_manager._peer_routes["peer1"] = mock_connector1
        sentinel._route_manager._peer_routes["peer2"] = mock_connector2

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        # Forward to specific peers, excluding peer2
        await sentinel.forward_to_peers(envelope, peers=["peer1"], exclude_peers=["peer2"], context=context)

        # Only peer1 should receive the envelope
        mock_connector1.send.assert_called_once_with(envelope)
        mock_connector2.send.assert_not_called()

    async def test_forward_to_peers_missing_peer(self, sentinel):
        """Test forward_to_peers when specified peer doesn't exist."""
        # Mock dispatch_envelope_event to return the envelope unchanged
        # Simulate the real behavior which finds the envelope by checking for .frame attribute
        def mock_dispatch_envelope_event(event, *args, **kwargs):
            # Find the envelope in the arguments - look for object with .frame attribute
            if "envelope" in kwargs:
                return kwargs["envelope"]
            for arg in args:
                if hasattr(arg, "frame"):
                    return arg
            return args[0] if args else None
        
        sentinel._dispatch_envelope_event = AsyncMock(side_effect=mock_dispatch_envelope_event)

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        # Should raise RuntimeError for missing peer
        with pytest.raises(RuntimeError, match="No route for peer segment"):
            await sentinel.forward_to_peers(envelope, peers=["non-existent-peer"], context=context)

    async def test_forward_upstream_with_flow(self, sentinel):
        """Test forward_upstream with flow tracking."""
        # Mock dispatch_envelope_event to return the envelope unchanged
        # Simulate the real behavior which finds the envelope by checking for .frame attribute
        def mock_dispatch_envelope_event(event, *args, **kwargs):
            # Find the envelope in the arguments - look for object with .frame attribute
            if "envelope" in kwargs:
                return kwargs["envelope"]
            for arg in args:
                if hasattr(arg, "frame"):
                    return arg
            return args[0] if args else None
        
        sentinel._dispatch_envelope_event = AsyncMock(side_effect=mock_dispatch_envelope_event)

        # Mock parent class forward_upstream
        with patch.object(
            type(sentinel).__bases__[0], "forward_upstream", new_callable=AsyncMock
        ) as mock_super:
            # Set up upstream connector
            mock_upstream = MagicMock()
            sentinel._upstream_connector = mock_upstream

            # Create envelope with flow_id
            envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
            envelope.flow_id = "test-flow"
            envelope.flow_flags = FlowFlags.RESET
            context = local_delivery_context()

            await sentinel.forward_upstream(envelope, context)

            # Verify super().forward_upstream was called
            mock_super.assert_called_once_with(envelope, context)

            # Verify flow was tracked and then forgotten
            assert "test-flow" not in sentinel._route_manager._flow_routes

    async def test_connect_to_peer_error_cases(self, sentinel, mock_admission_client):
        """Test _connect_to_peer error cases."""
        # Test missing attach_client
        sentinel.attach_client = None
        peer = Peer(admission_client=mock_admission_client)

        with pytest.raises(RuntimeError, match="Missing attach client"):
            await sentinel._connect_to_peer(peer)

        # Test missing admission_client
        sentinel.attach_client = MagicMock()
        peer_no_admission = Peer(admission_client=None)

        with pytest.raises(RuntimeError, match="Missing admission client"):
            await sentinel._connect_to_peer(peer_no_admission)

    async def test_connect_to_peer_success(self, sentinel, mock_admission_client, mock_attach_client):
        """Test successful _connect_to_peer."""
        sentinel.attach_client = mock_attach_client
        peer = Peer(admission_client=mock_admission_client)

        # Mock UpstreamSessionManager
        mock_session_manager = MagicMock()
        mock_session_manager.start = AsyncMock()
        mock_session_manager.system_id = "peer-session-id"

        with patch(
            "naylence.fame.sentinel.sentinel.UpstreamSessionManager",
            return_value=mock_session_manager,
        ):
            await sentinel._connect_to_peer(peer)

            # Verify session manager was created and started
            mock_session_manager.start.assert_called_once()

            # Verify peer route was registered
            assert "peer-session-id" in sentinel._peer_session_managers
            assert "peer-session-id" in sentinel._route_manager._peer_routes

    async def test_on_node_attach_to_peer(self, sentinel):
        """Test _on_node_attach_to_peer method."""
        # Mock _dispatch_event
        sentinel._dispatch_event = AsyncMock()

        mock_info = MagicMock(spec=AttachInfo)
        mock_connector = MagicMock(spec=FameConnector)

        await sentinel._on_node_attach_to_peer(mock_info, mock_connector)

        # Verify event was dispatched
        sentinel._dispatch_event.assert_called_once_with(
            "on_node_attach_to_peer", sentinel, mock_info, mock_connector
        )

    async def test_handle_inbound_from_peer(self, sentinel):
        """Test handle_inbound_from_peer method."""
        # Mock deliver
        sentinel.deliver = AsyncMock()

        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM)

        await sentinel.handle_inbound_from_peer(envelope, context)

        # Verify context was updated and deliver was called
        assert context.origin_type == DeliveryOriginType.PEER
        sentinel.deliver.assert_called_once_with(envelope, context=context)

    async def test_connect_to_peers_error_handling(
        self, sentinel, mock_admission_client, mock_attach_client
    ):
        """Test _connect_to_peers error handling."""
        sentinel.attach_client = mock_attach_client

        # Create peer that will cause an error
        peer = Peer(admission_client=mock_admission_client)
        sentinel._peers = [peer]

        # Mock spawn to return a task that raises an exception
        error_task = asyncio.create_task(self._failing_coroutine())
        sentinel.spawn = MagicMock(return_value=error_task)

        # Should re-raise the exception
        with pytest.raises(RuntimeError, match="Test error"):
            await sentinel._connect_to_peers()

    async def _failing_coroutine(self):
        """Helper coroutine that raises an exception."""
        raise RuntimeError("Test error")

    async def test_delayed_connector_cleanup(self, sentinel):
        """Test _delayed_connector_cleanup method."""
        mock_connector = MagicMock()
        sentinel._route_manager._safe_stop = AsyncMock()

        # Test successful cleanup
        await sentinel._delayed_connector_cleanup(mock_connector, 0.1)
        sentinel._route_manager._safe_stop.assert_called_once_with(mock_connector)

    async def test_delayed_connector_cleanup_error(self, sentinel):
        """Test _delayed_connector_cleanup with error."""
        mock_connector = MagicMock()
        sentinel._route_manager._safe_stop = AsyncMock(side_effect=Exception("Test error"))

        # Should not raise, just log error
        await sentinel._delayed_connector_cleanup(mock_connector, 0.1)
        sentinel._route_manager._safe_stop.assert_called_once_with(mock_connector)

    async def test_emit_delivery_nack(self, sentinel):
        """Test emit_delivery_nack method."""
        envelope = create_fame_envelope(frame=NodeHeartbeatFrame())
        context = local_delivery_context()

        # Mock build_router_state
        mock_state = MagicMock()
        sentinel.build_router_state = MagicMock(return_value=mock_state)

        with patch("naylence.fame.sentinel.router.emit_delivery_nack") as mock_emit:
            await sentinel.emit_delivery_nack(envelope, code="TEST_ERROR", context=context)

            mock_emit.assert_called_once_with(envelope, sentinel, mock_state, "TEST_ERROR", context)

    async def test_resolve_encryption_key_for_address(self, sentinel):
        """Test resolve_encryption_key_for_address method."""
        # Test with downstream route
        test_addr = FameAddress("service@/test")
        route_info = MagicMock()
        route_info.physical_path = "/test/path"
        sentinel._route_manager._downstream_addresses_routes[test_addr] = route_info

        result = await sentinel.resolve_encryption_key_for_address(test_addr)
        assert result is None  # TODO: Implementation returns None for now

        # Test with peer route
        peer_addr = FameAddress("service@/peer")
        sentinel._route_manager._peer_addresses_routes[peer_addr] = "peer-segment"

        result = await sentinel.resolve_encryption_key_for_address(peer_addr)
        assert result is None  # TODO: Implementation returns None for now

        # Test with unknown address
        unknown_addr = FameAddress("service@/unknown")
        result = await sentinel.resolve_encryption_key_for_address(unknown_addr)
        assert result is None

    async def test_remove_downstream_route(self, sentinel):
        """Test remove_downstream_route method."""
        sentinel._route_manager._remove_downstream_route = AsyncMock(return_value="removed")

        result = await sentinel.remove_downstream_route("test-segment", stop=True)

        sentinel._route_manager._remove_downstream_route.assert_called_once_with("test-segment", stop=True)
        assert result == "removed"

    async def test_remove_peer_route(self, sentinel):
        """Test remove_peer_route method."""
        sentinel._route_manager._remove_peer_route = AsyncMock(return_value="removed")

        result = await sentinel.remove_peer_route("test-peer", stop=False)

        sentinel._route_manager._remove_peer_route.assert_called_once_with("test-peer", stop=False)
        assert result == "removed"


if __name__ == "__main__":
    pytest.main([__file__])
