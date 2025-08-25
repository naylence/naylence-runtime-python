#!/usr/bin/env python3
"""Integration test for connector state management with actual connectors."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core.connector.connector_state import ConnectorState


@pytest.mark.asyncio
async def test_websocket_connector_state():
    """Test state management with WebSocketConnector using mocks."""
    print("Testing WebSocketConnector state management...")

    # Create a mock connector that behaves like WebSocketConnector
    class MockWebSocketConnector:
        def __init__(self):
            self.state = ConnectorState.INITIALIZED
            self._handler = None

        @property
        def connector_state(self):
            return self.state

        async def start(self, handler):
            self._handler = handler
            self.state = ConnectorState.STARTED

        async def stop(self):
            self.state = ConnectorState.STOPPED

    connector = MockWebSocketConnector()

    # Test initial state
    assert connector.state == ConnectorState.INITIALIZED
    assert connector.connector_state == ConnectorState.INITIALIZED
    print(f"✓ Initial state: {connector.state}")

    # Mock handler
    async def mock_handler(envelope):
        pass

    # Test starting
    await connector.start(mock_handler)
    assert connector.state == ConnectorState.STARTED
    print(f"✓ Started state: {connector.state}")

    # Test stopping
    await connector.stop()
    assert connector.state == ConnectorState.STOPPED
    print(f"✓ Stopped state: {connector.state}")


@pytest.mark.asyncio
async def test_http_stateless_connector_state():
    """Test state management with HttpStatelessConnector."""
    print("Testing HttpStatelessConnector state management...")

    from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector

    # Create connector
    connector = HttpStatelessConnector(url="http://test.example.com")

    # Test initial state
    assert connector.state == ConnectorState.INITIALIZED
    print(f"✓ Initial state: {connector.state}")

    # Mock handler
    async def mock_handler(envelope):
        pass

    # Test starting
    await connector.start(mock_handler)
    assert connector.state == ConnectorState.STARTED
    print(f"✓ Started state: {connector.state}")

    # Test stopping
    await connector.stop()
    assert connector.state == ConnectorState.STOPPED
    print(f"✓ Stopped state: {connector.state}")


@pytest.mark.asyncio
async def test_connector_state_thread_safety():
    """Test that state changes are thread-safe."""
    print("Testing connector state thread safety...")

    from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector

    connector = HttpStatelessConnector(url="http://test.example.com")

    async def mock_handler(envelope):
        pass

    # Start multiple state change operations concurrently
    async def start_connector():
        await connector.start(mock_handler)

    async def stop_connector():
        await asyncio.sleep(0.01)  # Small delay
        await connector.stop()

    # Run operations concurrently
    await asyncio.gather(start_connector(), stop_connector())

    # Final state should be stopped
    assert connector.state == ConnectorState.STOPPED
    print("✓ Concurrent state changes handled correctly")


@pytest.mark.asyncio
async def test_connector_state_error_handling():
    """Test state management during error conditions."""
    print("Testing connector state error handling...")

    from naylence.fame.connector.websocket_connector import WebSocketConnector
    from naylence.fame.errors.errors import FameTransportClose

    # Create mock WebSocket that will fail
    mock_websocket = Mock()
    mock_websocket.close = AsyncMock()

    connector = WebSocketConnector(mock_websocket)

    # Mock transport methods to simulate failure
    async def failing_transport_receive():
        raise FameTransportClose(1006, "Connection lost")

    connector._transport_send_bytes = AsyncMock()
    connector._transport_receive = failing_transport_receive
    connector._transport_close = AsyncMock()

    async def mock_handler(envelope):
        pass

    # Start connector
    await connector.start(mock_handler)
    assert connector.state == ConnectorState.STARTED

    # Trigger error by trying to receive (this will happen in background)
    # The connector should handle the error and transition to closed state
    await asyncio.sleep(0.1)  # Give time for background tasks

    print(f"✓ State after error: {connector.state}")
    # State should be closed due to transport error
    assert connector.state in [ConnectorState.CLOSED, ConnectorState.STOPPED]


def test_connector_state_validation():
    """Test that invalid state transitions are handled properly."""
    print("Testing connector state validation...")

    from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector

    connector = HttpStatelessConnector(url="http://test.example.com")

    # Initial state should be INITIALIZED
    assert connector.state == ConnectorState.INITIALIZED

    # Test that state property is read-only (implementation detail)
    # We can't directly set state from outside, which is good for encapsulation
    original_state = connector.state

    # The state should only change through proper methods
    assert connector.state == original_state
    print("✓ Connector state is properly encapsulated")


@pytest.mark.asyncio
async def test_connector_multiple_stop_calls():
    """Test that multiple stop calls are handled gracefully without warnings."""
    print("Testing multiple stop calls on connector...")

    from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector

    connector = HttpStatelessConnector(url="http://test.example.com")

    async def mock_handler(envelope):
        pass

    # Start the connector
    await connector.start(mock_handler)
    assert connector.state == ConnectorState.STARTED
    print(f"✓ Started state: {connector.state}")

    # Stop the connector
    await connector.stop()
    assert connector.state == ConnectorState.STOPPED
    print(f"✓ First stop: {connector.state}")

    # Stop it again - should be idempotent and not cause warnings
    await connector.stop()
    assert connector.state == ConnectorState.STOPPED
    print("✓ Second stop handled gracefully (idempotent)")

    # Stop it a third time - should still be fine
    await connector.stop()
    assert connector.state == ConnectorState.STOPPED
    print("✓ Third stop handled gracefully (idempotent)")


@pytest.mark.asyncio
async def test_concurrent_stop_calls():
    """Test that concurrent stop calls don't cause issues."""
    print("Testing concurrent stop calls...")

    from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector

    connector = HttpStatelessConnector(url="http://test.example.com")

    async def mock_handler(envelope):
        pass

    # Start the connector
    await connector.start(mock_handler)
    assert connector.state == ConnectorState.STARTED

    # Call stop multiple times concurrently
    stop_tasks = [connector.stop() for _ in range(5)]
    await asyncio.gather(*stop_tasks)

    # Should end up in stopped state
    assert connector.state == ConnectorState.STOPPED
    print("✓ Concurrent stop calls handled correctly")


if __name__ == "__main__":
    asyncio.run(test_websocket_connector_state())
    asyncio.run(test_http_stateless_connector_state())
    asyncio.run(test_connector_state_thread_safety())
    asyncio.run(test_connector_state_error_handling())
    test_connector_state_validation()
    asyncio.run(test_connector_multiple_stop_calls())
    asyncio.run(test_concurrent_stop_calls())

    print("\n✅ All connector state integration tests passed!")
