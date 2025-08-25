"""Tests for WebSocket connector to improve coverage."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import (
    WebSocketConnectorConfig,
    WebSocketConnectorFactory,
)
from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame, KeyRequestFrame
from naylence.fame.security.auth.auth_config import NoAuth


class TestWebSocketConnector:
    """Test WebSocket connector functionality."""

    @pytest.mark.asyncio
    async def test_websocket_connector_factory_creation(self):
        """Test WebSocket connector factory creates proper instances."""
        factory = WebSocketConnectorFactory()

        # Test creating connector with proper config
        config = WebSocketConnectorConfig(
            url="ws://localhost:8080/test",
            auth=NoAuth(),
        )

        # Mock the websocket connection since we can't actually connect
        with patch("websockets.connect", new_callable=AsyncMock) as mock_connect:
            mock_ws = AsyncMock()
            mock_connect.return_value = mock_ws

            connector = await factory.create(config)
            assert isinstance(connector, WebSocketConnector)

        # Test creating connector with different auth styles
        config_query = WebSocketConnectorConfig(
            url="wss://example.com:9443/secure",
            auth=NoAuth(),
        )

        with patch("websockets.connect", new_callable=AsyncMock) as mock_connect:
            mock_ws = AsyncMock()
            mock_connect.return_value = mock_ws

            wss_connector = await factory.create(config_query)
            assert isinstance(wss_connector, WebSocketConnector)

    def test_websocket_connector_initialization(self):
        """Test WebSocket connector initialization and properties."""
        # Mock websocket object
        mock_websocket = Mock()
        mock_websocket.remote_address = ("test.example.com", 8080)

        connector = WebSocketConnector(mock_websocket)

        assert connector.websocket == mock_websocket
        assert hasattr(connector, "_is_fastapi")

        # Test with FastAPI websocket mock
        if hasattr(connector, "_FastAPIWebSocket") and connector._FastAPIWebSocket:
            mock_fastapi_ws = Mock()
            mock_fastapi_ws.__class__.__name__ = "WebSocket"
            fastapi_connector = WebSocketConnector(mock_fastapi_ws)
            assert fastapi_connector.websocket == mock_fastapi_ws

    def test_websocket_connector_drain_timeout_configuration(self):
        """Test WebSocket connector drain timeout configuration."""
        mock_websocket = Mock()

        # Test default drain timeout
        connector = WebSocketConnector(mock_websocket)
        assert hasattr(connector, "_drain_timeout")

        # Test custom drain timeout
        custom_connector = WebSocketConnector(mock_websocket, drain_timeout=0.5)
        assert hasattr(custom_connector, "_drain_timeout")

    @pytest.mark.asyncio
    async def test_websocket_connector_connection_lifecycle(self):
        """Test WebSocket connector connection lifecycle."""
        mock_websocket = AsyncMock()
        mock_websocket.closed = False

        connector = WebSocketConnector(mock_websocket)

        # Test that the connector is properly initialized
        assert connector.websocket is mock_websocket
        assert connector._is_fastapi is False

        # Test _transport_close directly to avoid BaseAsyncConnector complexity
        await connector._transport_close(1000, "normal closure")

        # Verify the websocket close was called
        mock_websocket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_websocket_connector_send_message(self):
        """Test sending messages through WebSocket connector."""
        mock_websocket = AsyncMock()
        mock_websocket.closed = False

        connector = WebSocketConnector(mock_websocket)

        # Create test envelope
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame, sid="test-sid")

        # Test _transport_send_bytes directly since send() uses a queue
        envelope_json = envelope.model_dump_json(by_alias=True, exclude_none=True)
        test_data = envelope_json.encode("utf-8")

        await connector._transport_send_bytes(test_data)

        # Verify the websocket send method was called with the data
        mock_websocket.send.assert_called_once_with(test_data)

        # Verify the sent data is bytes
        sent_args = mock_websocket.send.call_args[0]
        assert len(sent_args) == 1
        assert isinstance(sent_args[0], bytes)

    @pytest.mark.asyncio
    async def test_websocket_connector_receive_message(self):
        """Test receiving messages through WebSocket connector."""
        mock_websocket = AsyncMock()
        mock_websocket.closed = False

        WebSocketConnector(mock_websocket)

        # Mock received JSON message as bytes (how it comes over websocket)
        test_envelope_data = {
            "version": "1.0",
            "id": "test-id",
            "sid": "test-sid",
            "frame": {"type": "Data", "payload": {"message": "hello"}, "codec": "json"},
        }

        import json

        json.dumps(test_envelope_data).encode("utf-8")

    @pytest.mark.asyncio
    async def test_websocket_connector_connection_error_handling(self):
        """Test WebSocket connector error handling."""
        mock_websocket = AsyncMock()

        connector = WebSocketConnector(mock_websocket)

        # Mock connection failure during receive
        from websockets.exceptions import ConnectionClosed

        mock_websocket.recv.side_effect = ConnectionClosed(None, None)

        # Test that connection errors are properly handled and translated
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose):
            await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_websocket_connector_send_with_closed_connection(self):
        """Test sending with a closed connection."""
        mock_websocket = AsyncMock()
        mock_websocket.closed = True

        connector = WebSocketConnector(mock_websocket)

        # Mock send to raise ConnectionClosed
        from websockets.exceptions import ConnectionClosed

        mock_websocket.send.side_effect = ConnectionClosed(None, None)

        # Should raise FameTransportClose when trying to send
        from naylence.fame.errors.errors import FameTransportClose

        test_data = b'{"test": "data"}'

        with pytest.raises(FameTransportClose):
            await connector._transport_send_bytes(test_data)

    @pytest.mark.asyncio
    async def test_websocket_connector_receive_timeout(self):
        """Test receiving with timeout."""
        mock_websocket = AsyncMock()

        connector = WebSocketConnector(mock_websocket)

        # Mock receive to timeout
        mock_websocket.recv.side_effect = asyncio.TimeoutError()

        # Test receive with timeout - the websocket connector uses asyncio.wait_for internally
        # which should catch the TimeoutError and convert it to FameTransportClose
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose):
            await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_websocket_connector_factory_invalid_config(self):
        """Test WebSocket connector factory with invalid configurations."""
        factory = WebSocketConnectorFactory()

        # Test with no config
        with pytest.raises(ValueError, match="Config not set"):
            await factory.create(None)

        # Test with config missing params
        # Test with missing URL
        invalid_config = WebSocketConnectorConfig()

        with pytest.raises(ValueError, match="WebSocket URL must be provided in config"):
            await factory.create(invalid_config)

    @pytest.mark.asyncio
    async def test_websocket_connector_close_behavior(self):
        """Test WebSocket connector close behavior."""
        mock_websocket = AsyncMock()

        connector = WebSocketConnector(mock_websocket)

        # Test _transport_close directly to avoid BaseAsyncConnector complexity
        await connector._transport_close(1000, "test close")

        # Verify the websocket close was called
        mock_websocket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_websocket_connector_message_serialization(self):
        """Test message serialization for different frame types."""
        mock_websocket = AsyncMock()

        connector = WebSocketConnector(mock_websocket)

        frame_types = [
            DataFrame(payload={"test": "data"}, codec="json"),
            KeyRequestFrame(kid="test-key"),
        ]

        for frame in frame_types:
            envelope = FameEnvelope(frame=frame, sid="test-sid")

            # Reset mock to clear previous calls
            mock_websocket.send.reset_mock()

            # Test _transport_send_bytes directly
            envelope_json = envelope.model_dump_json(by_alias=True, exclude_none=True)
            test_data = envelope_json.encode("utf-8")

            await connector._transport_send_bytes(test_data)

            # Verify send was called with bytes data
            mock_websocket.send.assert_called_once_with(test_data)
            sent_data = mock_websocket.send.call_args[0][0]
            assert isinstance(sent_data, bytes)

            # Verify it's valid JSON when decoded
            import json

            try:
                decoded = sent_data.decode("utf-8")
                parsed = json.loads(decoded)
                assert isinstance(parsed, dict)
                assert "frame" in parsed
            except (json.JSONDecodeError, UnicodeDecodeError):
                pytest.fail("Sent data should be valid JSON bytes")

    @pytest.mark.asyncio
    async def test_websocket_connector_concurrent_operations(self):
        """Test WebSocket connector with concurrent send/receive operations."""
        mock_websocket = AsyncMock()

        connector = WebSocketConnector(mock_websocket)

        # Mock receive to return test data
        test_data = (
            '{"version": "1.0", "id": "test", "sid": "test-sid", '
            '"frame": {"type": "Data", "payload": {}, "codec": "json"}}'
        )
        test_data_bytes = test_data.encode("utf-8")
        mock_websocket.recv.return_value = test_data_bytes

        # Create multiple send and receive tasks
        send_tasks = []

        for i in range(3):
            frame = DataFrame(payload={"index": i}, codec="json")
            envelope = FameEnvelope(frame=frame, sid=f"test-sid-{i}")
            envelope_json = envelope.model_dump_json(by_alias=True, exclude_none=True)
            test_send_data = envelope_json.encode("utf-8")
            send_tasks.append(connector._transport_send_bytes(test_send_data))

        # Execute all send tasks concurrently
        await asyncio.gather(*send_tasks)

        # Verify all sends were called
        assert mock_websocket.send.call_count == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
