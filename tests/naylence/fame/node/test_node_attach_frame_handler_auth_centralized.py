"""
Test that NodeAttachFrameHandler no longer handles authorization directly
since authorization is now centralized in DefaultSecurityManager.on_deliver()
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import (
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    NodeAttachFrame,
)
from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler


@pytest.mark.asyncio
async def test_node_attach_frame_handler_no_authorization_checks():
    """Test that NodeAttachFrameHandler no longer performs authorization checks"""

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()

    mock_security_manager = MagicMock()
    mock_security_manager.on_child_attach = AsyncMock()
    mock_routing_node.security_manager = mock_security_manager

    mock_key_manager = MagicMock()

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.register_downstream_route = AsyncMock()
    mock_route_manager.expire_route_later = AsyncMock()

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
    connector_config = ConnectorConfig(type="test")

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (
        mock_connector,
        mock_attached,
        mock_buffer,
    )

    # Create handler (no authorizer parameter needed)
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

    # Create context - if envelope reaches here, authorization already passed
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler - should always succeed since auth is centralized
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"
    assert sent_envelope.corr_id == "test-correlation-id", "Correlation ID should match"

    # Verify that route was registered
    mock_route_manager.register_downstream_route.assert_called_once_with(attached_system_id, mock_connector)

    # Verify no connection close was called (since it succeeded)
    mock_connector.close.assert_not_called()


@pytest.mark.asyncio
async def test_node_attach_frame_handler_certificate_validation_still_works():
    """Test that certificate validation still happens even though authorization is centralized"""

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()

    mock_security_manager = MagicMock()
    mock_security_manager.on_child_attach = AsyncMock()
    mock_routing_node.security_manager = mock_security_manager

    mock_key_manager = MagicMock()

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.register_downstream_route = AsyncMock()
    mock_route_manager.expire_route_later = AsyncMock()

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
    connector_config = ConnectorConfig(type="test")

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (
        mock_connector,
        mock_attached,
        mock_buffer,
    )

    # Create a mock validator
    mock_validator = AsyncMock()
    mock_validator.validate_keys = AsyncMock(return_value=[])

    # Create handler
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        key_manager=mock_key_manager,
        route_manager=mock_route_manager,
        attachment_key_validator=mock_validator,
    )

    # Create attach frame with valid keys (certificate validation should pass)
    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=None,  # No keys provided = validation passes
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")

    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    try:
        # Call the handler - should succeed
        await handler.accept_node_attach(envelope, context)

        # Verify validator was called first
        mock_validator.validate_keys.assert_called_once_with(None)

        # Verify successful attachment
        assert mock_connector.send.called, "Expected send to be called but it wasn't"
        sent_envelope = mock_connector.send.call_args[0][0]
        assert sent_envelope.frame.ok, "Should succeed with valid certificates"

    finally:
        pass  # No cleanup needed since we used proper mocking


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_node_attach_frame_handler_no_authorization_checks()
        await test_node_attach_frame_handler_certificate_validation_still_works()
        print("All tests passed!")

    asyncio.run(run_tests())
