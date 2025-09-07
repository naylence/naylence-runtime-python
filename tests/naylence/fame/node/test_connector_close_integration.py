import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import DeliveryOriginType, FameEnvelope, NodeAttachFrame
from naylence.fame.core.connector.connector import FameConnector
from naylence.fame.node.node_context import FameDeliveryContext
from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler


class MockConnector(FameConnector):
    """Mock connector for testing"""

    def __init__(self):
        self.sent_envelopes = []
        self.close_calls = []

    async def send(self, envelope):
        self.sent_envelopes.append(envelope)

    async def close(self, code: int = 1000, reason: str = "normal closure"):
        self.close_calls.append((code, reason))


@pytest.mark.asyncio
async def test_node_attach_frame_handler_with_real_connector():
    """Test that the node attach frame handler works with a real connector that has close method"""

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node._dispatch_envelope_event = (
        AsyncMock()
    )  # Add envelope event dispatch mock  # Make this async

    # Mock security manager
    mock_security_manager = MagicMock()
    mock_security_manager.get_shareable_keys = MagicMock(return_value=None)
    mock_routing_node.security_manager = mock_security_manager

    mock_key_manager = AsyncMock()

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.expire_route_later = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()  # Add this mock
    mock_route_manager.downstream_route_store = AsyncMock()  # Add route store mock

    # Create real connector
    connector = MockConnector()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = ConnectorConfig(type="test")  # Use real ConnectorConfig instead of MagicMock

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (
        connector,
        mock_attached,
        mock_buffer,
    )

    # Create handler (no authorizer needed since authorization is centralized)
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

    # Create context
    context = FameDeliveryContext(
        from_connector=connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler - should succeed since authorization is centralized
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent (authorization happens centrally now)
    assert len(connector.sent_envelopes) == 1, "Acknowledgment should have been sent"
    sent_envelope = connector.sent_envelopes[0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"
    assert sent_envelope.corr_id == "test-correlation-id", "Correlation ID should match"

    # Verify that connection was NOT closed (successful attachment)
    await asyncio.sleep(0.2)  # Give time for any background tasks

    # Wait for all background tasks to complete
    if handler._tasks:
        await asyncio.gather(*handler._tasks, return_exceptions=True)

    # Verify that connector.close was NOT called (successful case)
    assert len(connector.close_calls) == 0, "Connection should not have been closed on success"


@pytest.mark.asyncio
async def test_connector_close_method_standalone():
    """Test that the connector close method works correctly"""

    connector = MockConnector()

    # Start the connector to initialize internal tasks
    mock_handler = AsyncMock()
    await connector.start(mock_handler)

    # Test close with custom code and reason
    await connector.close(4403, "attach-unauthorized")

    assert len(connector.close_calls) == 1
    code, reason = connector.close_calls[0]
    assert code == 4403
    assert reason == "attach-unauthorized"


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_connector_close_method_standalone()
        await test_node_attach_frame_handler_with_real_connector()
        print("✅ All tests passed!")

    asyncio.run(run_tests())
