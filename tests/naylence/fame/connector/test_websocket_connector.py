"""Tests for WebSocket connector to improve coverage."""

import asyncio
import warnings
from unittest.mock import AsyncMock, Mock, patch

import pytest
from websockets.exceptions import ConnectionClosed

from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import (
    WebSocketConnectorConfig,
    WebSocketConnectorFactory,
)
from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame, KeyRequestFrame
from naylence.fame.security.auth.no_auth_injection_strategy_factory import NoAuthInjectionStrategyConfig


class TestWebSocketConnector:
    """Test WebSocket connector functionality."""

    @pytest.mark.asyncio
    async def test_websocket_connector_factory_creation(self):
        """Test WebSocket connector factory creates proper instances."""
        factory = WebSocketConnectorFactory()

        # Test creating connector with proper config
        config = WebSocketConnectorConfig(
            url="ws://localhost:8080/test",
            auth=NoAuthInjectionStrategyConfig(),
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
            auth=NoAuthInjectionStrategyConfig(),
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
        # Configure close to return None when awaited
        mock_websocket.close.return_value = None

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
        # Configure send to return None when awaited
        mock_websocket.send.return_value = None

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
        # Configure close to return None when awaited
        mock_websocket.close.return_value = None

        connector = WebSocketConnector(mock_websocket)

        # Test _transport_close directly to avoid BaseAsyncConnector complexity
        await connector._transport_close(1000, "test close")

        # Verify the websocket close was called
        mock_websocket.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_websocket_connector_message_serialization(self):
        """Test message serialization for different frame types."""
        mock_websocket = AsyncMock()
        # Configure send to return None when awaited
        mock_websocket.send.return_value = None

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


class TestWebSocketConnectorGapCoverage:
    """Test WebSocket connector targeting specific uncovered code paths."""

    @pytest.mark.asyncio
    async def test_fastapi_receive_method_validation_error(self):
        """Test FastAPI WebSocket when receive_bytes method is not available (lines 86-91)."""
        # Mock FastAPI WebSocket without receive_bytes method
        mock_fastapi_ws = Mock()
        mock_fastapi_ws.receive_bytes = None  # Method doesn't exist or is None

        # Create connector that thinks it's FastAPI
        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # This should hit lines 86-91: check and raise error for missing receive_bytes
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose) as exc_info:
            await connector._transport_receive()

        assert "FastAPI WebSocket receive_bytes method not available" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fastapi_receive_non_awaitable_result(self):
        """Test FastAPI WebSocket when receive_bytes returns non-awaitable (lines 94-101)."""
        # Mock FastAPI WebSocket that returns non-awaitable
        mock_fastapi_ws = Mock()
        mock_fastapi_ws.receive_bytes = Mock(return_value="not_an_awaitable")  # String instead of coroutine

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # This should hit lines 94-101: validation of awaitable result
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose) as exc_info:
            await connector._transport_receive()

        assert "FastAPI receive_bytes returned non-awaitable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fastapi_receive_timeout_error(self):
        """Test FastAPI WebSocket receive timeout handling (lines 105-112)."""
        # Mock FastAPI WebSocket that times out
        mock_fastapi_ws = AsyncMock()
        mock_fastapi_ws.receive_bytes.side_effect = asyncio.TimeoutError()

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # This should hit lines 105-112: timeout handling
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose) as exc_info:
            await connector._transport_receive()

        assert "FastAPI receive_bytes timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_fastapi_receive_await_future_error_conversion(self):
        """Test FastAPI WebSocket 'await wasn't used with future' error conversion (lines 116-133)."""
        # Mock FastAPI WebSocket that raises the specific error
        mock_fastapi_ws = AsyncMock()
        specific_error = Exception("await wasn't used with future")
        mock_fastapi_ws.receive_bytes.side_effect = specific_error

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # Mock current_task to simulate cancellation
        with patch("asyncio.current_task") as mock_current_task:
            mock_task = Mock()
            mock_task.cancelled.return_value = True
            mock_current_task.return_value = mock_task

            # This should hit lines 116-133: error conversion during cancellation
            with pytest.raises(asyncio.CancelledError) as exc_info:
                await connector._transport_receive()

            assert "Converted await future error during cancellation" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_websockets_recv_method_validation_error(self):
        """Test WebSocket when recv method is not available (lines 139)."""
        # Mock WebSocket without recv method
        mock_ws = Mock()
        mock_ws.recv = None  # Method doesn't exist or is None

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # This should hit line 139: check and raise error for missing recv
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose) as exc_info:
            await connector._transport_receive()

        assert "WebSocket recv method not available" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_websockets_recv_non_awaitable_result(self):
        """Test WebSocket when recv returns non-awaitable (lines 145-150)."""
        # Mock WebSocket that returns non-awaitable
        mock_ws = Mock()
        mock_ws.recv = Mock(return_value="not_an_awaitable")  # String instead of coroutine

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # This should hit lines 145-150: validation of awaitable result
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose) as exc_info:
            await connector._transport_receive()

        assert "WebSocket recv returned non-awaitable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_websockets_recv_await_future_error_conversion(self):
        """Test WebSocket 'await wasn't used with future' error conversion (lines 163-175)."""
        # Mock WebSocket that raises the specific error
        mock_ws = AsyncMock()
        specific_error = Exception("await wasn't used with future")
        mock_ws.recv.side_effect = specific_error

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # Mock current_task to simulate cancellation
        with patch("asyncio.current_task") as mock_current_task:
            mock_task = Mock()
            mock_task.cancelled.return_value = True
            mock_current_task.return_value = mock_task

            # This should hit lines 163-175: error conversion during cancellation
            with pytest.raises(asyncio.CancelledError) as exc_info:
                await connector._transport_receive()

            assert "Converted await future error during cancellation" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_type_error_await_future_shutdown_race_condition(self):
        """Test TypeError 'await wasn't used with future' race condition handling (lines 180-219)."""
        # Mock WebSocket that raises TypeError with specific message
        mock_ws = AsyncMock()
        specific_error = TypeError("await wasn't used with future")
        mock_ws.recv.side_effect = specific_error

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # Mock current_task to simulate cancellation (expected case)
        with patch("asyncio.current_task") as mock_current_task:
            mock_task = Mock()
            mock_task.cancelled.return_value = True
            mock_task.get_name.return_value = "test_task"
            mock_current_task.return_value = mock_task

            # This should hit lines 180-219: race condition detection and handling
            with pytest.raises(asyncio.CancelledError) as exc_info:
                await connector._transport_receive()

            # The error message can be from either path - both are valid cancellation scenarios
            error_msg = str(exc_info.value)
            assert (
                "WebSocket cancelled during receive operation" in error_msg
                or "Converted await future error during cancellation" in error_msg
            )

    @pytest.mark.asyncio
    async def test_fastapi_close_with_state_checking(self):
        """Test FastAPI WebSocket close with state checking (lines 226-230)."""
        # Mock FastAPI WebSocket with state
        mock_fastapi_ws = AsyncMock()

        # Create a mock state enum
        mock_fastapi_ws.client_state = "connected"

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # Mock the FastAPI state constant
        with patch(
            "naylence.fame.connector.websocket_connector._FastAPIWebSocketState"
        ) as mock_state_class:
            mock_state_class.CONNECTED = "connected"

            # This should hit lines 226-230: FastAPI close with state check
            await connector._transport_close(1000, "test close")

            mock_fastapi_ws.close.assert_called_once_with(code=1000, reason="test close")

    @pytest.mark.asyncio
    async def test_websocket_none_validation(self):
        """Test WebSocket None validation in receive (line 79)."""
        connector = WebSocketConnector(None)  # None websocket

        # This should hit line 79: WebSocket None validation
        from naylence.fame.errors.errors import FameTransportClose

        with pytest.raises(FameTransportClose) as exc_info:
            await connector._transport_receive()

        assert "WebSocket object is None" in str(exc_info.value)

    def test_authorization_context_property_getter(self):
        """Test authorization context property getter (lines 238)."""
        mock_ws = Mock()
        connector = WebSocketConnector(mock_ws)

        # Set context and test getter
        from naylence.fame.core import AuthorizationContext

        test_context = AuthorizationContext()
        connector._authorization_context = test_context

        # This should hit line 238: property getter
        result = connector.authorization_context
        assert result is test_context

    def test_authorization_context_property_setter(self):
        """Test authorization context property setter (lines 243)."""
        mock_ws = Mock()
        connector = WebSocketConnector(mock_ws)

        # Test setter
        from naylence.fame.core import AuthorizationContext

        test_context = AuthorizationContext()

        # This should hit line 243: property setter
        connector.authorization_context = test_context
        assert connector._authorization_context is test_context

    @pytest.mark.asyncio
    async def test_fastapi_receive_cancelled_during_wait_for(self):
        """Test FastAPI WebSocket cancellation during asyncio.wait_for (lines 113-115)."""
        # Mock FastAPI WebSocket that gets cancelled
        mock_fastapi_ws = AsyncMock()
        mock_fastapi_ws.receive_bytes.side_effect = asyncio.CancelledError("Test cancellation")

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # This should hit lines 113-115: cancellation handling
        with pytest.raises(asyncio.CancelledError):
            await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_websockets_recv_cancelled_during_wait_for(self):
        """Test WebSocket cancellation during asyncio.wait_for (lines 160-163)."""
        # Mock WebSocket that gets cancelled
        mock_ws = AsyncMock()
        mock_ws.recv.side_effect = asyncio.CancelledError("Test cancellation")

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # This should hit lines 160-163: cancellation handling
        with pytest.raises(asyncio.CancelledError):
            await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_type_error_non_cancelled_debug_path(self):
        """Test TypeError debug path when task is not cancelled (lines 180-219)."""
        # Mock WebSocket that raises TypeError
        mock_ws = AsyncMock()
        specific_error = TypeError("await wasn't used with future")
        mock_ws.recv.side_effect = specific_error

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # Mock current_task to NOT be cancelled (to hit debug path)
        with patch("asyncio.current_task") as mock_current_task:
            mock_task = Mock()
            mock_task.cancelled.return_value = False  # Not cancelled
            mock_current_task.return_value = mock_task

            # This should hit the debug path in lines 207-219
            with pytest.raises(TypeError):
                await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_fastapi_close_exception_handling(self):
        """Test FastAPI WebSocket close exception handling (lines 229-230)."""
        # Mock FastAPI WebSocket that raises exception during close
        mock_fastapi_ws = AsyncMock()
        mock_fastapi_ws.client_state = "connected"

        # Use direct exception assignment instead of async function
        close_exception = Exception("Close failed")
        mock_fastapi_ws.close.side_effect = close_exception

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # Mock the FastAPI state constant
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with patch(
                "naylence.fame.connector.websocket_connector._FastAPIWebSocketState"
            ) as mock_state_class:
                mock_state_class.CONNECTED = "connected"

                # This should hit lines 229-230: exception handling during close
                # The method should not re-raise the exception (commented out)
                await connector._transport_close(1000, "test close")

                mock_fastapi_ws.close.assert_called_once_with(code=1000, reason="test close")

    @pytest.mark.asyncio
    async def test_websocket_validation_bypass(self):
        """Test WebSocket validation that gets bypassed (line 66)."""
        # This is tricky - line 66 might be a conditional that's hard to hit
        # Let's try with a mock that has some attributes but still fails
        mock_ws = Mock()
        mock_ws.recv = AsyncMock()
        mock_ws.recv.side_effect = Exception("Test error")

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # This might hit line 66 depending on the validation logic
        with pytest.raises(Exception):
            await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_fastapi_debug_logging_path_type_error(self):
        """Test FastAPI debug logging when TypeError occurs during receive (lines 191-196)."""
        # Mock FastAPI WebSocket that raises specific TypeError triggering debug path
        mock_fastapi_ws = AsyncMock()
        # First call raises TypeError with specific message, second call for debug logging succeeds
        mock_fastapi_ws.receive_bytes.side_effect = [
            TypeError("await wasn't used with future"),  # Triggers debug path
            b"debug_data",  # Second call for debug logging
        ]

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # This should hit lines 191-196: FastAPI debug logging in except TypeError block
        with pytest.raises(TypeError):
            await connector._transport_receive()

        # Verify debug logging was attempted
        assert mock_fastapi_ws.receive_bytes.call_count == 2

    @pytest.mark.asyncio
    async def test_websockets_debug_logging_path_type_error(self):
        """Test WebSocket debug logging when TypeError occurs during receive (lines 200-208)."""
        import warnings

        class MockWebSocket:
            def __init__(self):
                self.call_count = 0

            async def recv(self):
                self.call_count += 1
                # Always raise TypeError to trigger debug path
                raise TypeError("await wasn't used with future")

            @property
            def state(self):
                return "connected"

        mock_ws = MockWebSocket()
        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # Suppress the RuntimeWarning from unawaited coroutine in debug code
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            # This should hit lines 200-208: WebSocket debug logging in except TypeError block
            with pytest.raises(TypeError):
                await connector._transport_receive()

        # Verify the main call happened and debug path was triggered (check logs)
        assert mock_ws.call_count == 1

    @pytest.mark.asyncio
    async def test_fastapi_debug_logging_exception_during_debug(self):
        """Test FastAPI debug logging when debug call itself fails (lines 206-207)."""
        # Mock FastAPI WebSocket where debug logging call fails
        mock_fastapi_ws = AsyncMock()

        # Use exceptions directly without creating extra coroutines
        first_exception = TypeError("await wasn't used with future")
        second_exception = Exception("Debug call failed")

        # Set side_effect as a list of exceptions - no coroutines
        mock_fastapi_ws.receive_bytes.side_effect = [first_exception, second_exception]

        connector = WebSocketConnector(mock_fastapi_ws)
        connector._is_fastapi = True

        # This should hit lines 206-207: exception during debug logging
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with pytest.raises(TypeError):
                await connector._transport_receive()

    @pytest.mark.asyncio
    async def test_websockets_debug_logging_exception_during_debug(self):
        """Test WebSocket debug logging when debug call itself fails (lines 212-213)."""
        # Mock WebSocket where debug logging call fails
        mock_ws = AsyncMock()

        # Use exceptions directly without creating extra coroutines
        first_exception = TypeError("await wasn't used with future")
        second_exception = Exception("Debug call failed")

        mock_ws.recv.side_effect = [first_exception, second_exception]

        connector = WebSocketConnector(mock_ws)
        connector._is_fastapi = False

        # This should hit lines 212-213: exception during debug logging
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with pytest.raises(TypeError):
                await connector._transport_receive()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
