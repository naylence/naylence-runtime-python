from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import DeliveryOriginType, FameEnvelope, NodeAttachFrame
from naylence.fame.node.node_context import FameDeliveryContext
from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler


class MockConnectorConfig(ConnectorConfig):
    """Minimal connector config for testing."""

    type: str = "test"
    ttl: int = 3600
    durable: bool = False


@pytest.mark.asyncio
async def test_node_attach_frame_handler_no_longer_handles_authorization():
    """Test that NodeAttachFrameHandler no longer performs authorization checks"""

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"  # Should be string, not int
    mock_routing_node._dispatch_event = AsyncMock()  # Add event dispatch mock

    # Mock security manager with async on_child_attach
    mock_security_manager = MagicMock()
    mock_security_manager.on_child_attach = AsyncMock()
    mock_routing_node.security_manager = mock_security_manager

    mock_key_manager = MagicMock()

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.expire_route_later = AsyncMock()  # Make it async

    # Mock route stores
    mock_downstream_route_store = AsyncMock()
    mock_peer_route_store = AsyncMock()
    mock_route_manager.downstream_route_store = mock_downstream_route_store
    mock_route_manager._peer_route_store = mock_peer_route_store

    # Set up pending route data
    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()  # Use proper config instead of None

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (
        mock_connector,
        mock_attached,
        mock_buffer,
    )

    # Create handler (authorization is now centralized, no authorizer needed)
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        key_manager=mock_key_manager,
        route_manager=mock_route_manager,
    )

    # Create attach frame (no longer includes attach_token)
    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")

    # Create context - if envelope reaches here, authorization has already passed
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Mock downstream route registration
    mock_route_manager.register_downstream_route = AsyncMock()

    # Call the handler - should always succeed since auth is centralized
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent (no auth failure)
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"
    assert sent_envelope.corr_id == "test-correlation-id", "Correlation ID should match"

    # Verify that route was registered
    mock_route_manager.register_downstream_route.assert_called_once_with(attached_system_id, mock_connector)


@pytest.mark.asyncio
async def test_node_attach_frame_handler_still_works_successfully():
    """Test that successful attachment still works after removing authorization"""

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"  # Should be string, not int
    mock_routing_node._dispatch_event = AsyncMock()  # Add event dispatch mock

    # Mock security manager with async on_child_attach
    mock_security_manager = MagicMock()
    mock_security_manager.on_child_attach = AsyncMock()
    mock_routing_node.security_manager = mock_security_manager

    mock_key_manager = AsyncMock()

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.register_downstream_route = AsyncMock()
    mock_route_manager.expire_route_later = AsyncMock()  # Make it async

    # Mock route stores
    mock_downstream_route_store = AsyncMock()
    mock_peer_route_store = AsyncMock()
    mock_route_manager.downstream_route_store = mock_downstream_route_store
    mock_route_manager._peer_route_store = mock_peer_route_store

    # Set up pending route data
    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()  # Use proper config instead of None

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (
        mock_connector,
        mock_attached,
        mock_buffer,
    )

    # Create handler (authorization is now centralized, no authorizer needed)
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        key_manager=mock_key_manager,
        route_manager=mock_route_manager,
    )

    # Create attach frame
    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")

    # Create context
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler - this should work normally
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Positive acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"
    assert sent_envelope.corr_id == "test-correlation-id", "Correlation ID should match"

    # Verify that route was registered
    mock_route_manager.register_downstream_route.assert_called_once_with(attached_system_id, mock_connector)


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_node_attach_frame_handler_no_longer_handles_authorization()
        await test_node_attach_frame_handler_still_works_successfully()
        print("All tests passed!")

    asyncio.run(run_tests())
