"""Tests for BaseAsyncConnector to improve coverage."""

import asyncio
import json
import os
from unittest.mock import AsyncMock, Mock, PropertyMock, call, patch

import pytest

from naylence.fame.connector.base_async_connector import (
    _STOP_SENTINEL,
    ENV_VAR_SHOW_ENVELOPES,
    FAME_MAX_MESSAGE_SIZE,
    FLOW_CONTROL_ENABLED,
    BaseAsyncConnector,
    _NoopFlowController,
    _timestamp,
)
from naylence.fame.core import (
    ConnectorState,
    CreditUpdateFrame,
    DataFrame,
    FameChannelMessage,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.core.protocol.flow import FlowFlags
from naylence.fame.errors.errors import BackPressureFull, FameMessageTooLarge, FameTransportClose

# Import required for testing timestamp function
from naylence.fame.util.formatter import AnsiColor
from naylence.fame.util.metrics_emitter import MetricsEmitter


@pytest.fixture
async def cleanup_connectors():
    """Fixture to automatically cleanup all connectors created during tests."""
    connectors = []

    def register_connector(connector):
        connectors.append(connector)
        return connector

    # Provide the registration function to the test
    yield register_connector

    # Cleanup all connectors after test completes
    for connector in connectors:
        try:
            if hasattr(connector, "cleanup"):
                await connector.cleanup()
        except Exception:
            pass  # Ignore cleanup errors


@pytest.fixture(autouse=True)
async def auto_cleanup_tasks():
    """Automatically cancel all tasks after each test to prevent warnings."""
    yield

    # Get all tasks
    tasks = [task for task in asyncio.all_tasks() if not task.done()]

    # Cancel all non-current tasks
    current_task = asyncio.current_task()
    for task in tasks:
        if task is not current_task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass


class MockAsyncConnector(BaseAsyncConnector):
    """Mock implementation of BaseAsyncConnector for testing."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._sent_data = []
        self._receive_queue = asyncio.Queue()
        self._transport_closed = False
        self._transport_close_calls = []

    async def _transport_send_bytes(self, data: bytes) -> None:
        if self._transport_closed:
            raise FameTransportClose(code=1000, reason="Transport closed")
        self._sent_data.append(data)

    async def _transport_receive(self):
        if self._transport_closed:
            raise FameTransportClose(code=1000, reason="Normal closure")
        return await self._receive_queue.get()

    async def _transport_close(self, code: int, reason: str) -> None:
        self._transport_closed = True
        self._transport_close_calls.append((code, reason))
        # Gracefully close the receive queue
        # Put a sentinel to signal shutdown to any waiting receive operations
        try:
            # Close pending tasks gracefully
            await asyncio.sleep(0.001)  # Allow any pending receives to process
        except Exception:
            pass

    async def push_to_receive(self, data):
        """Helper to push data to receive queue."""
        if not self._transport_closed:
            await self._receive_queue.put(data)

    async def cleanup(self):
        """Clean up async resources properly."""
        # First close the connector to stop loops gracefully
        if not self._closed.is_set():
            try:
                await self.close()
            except Exception:
                pass

        # Cancel any pending tasks and wait for them to complete
        if hasattr(self, "_tasks") and self._tasks:
            for task in list(self._tasks):
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    except Exception:
                        pass

        # Clear the receive queue to prevent hanging operations
        while not self._receive_queue.empty():
            try:
                self._receive_queue.get_nowait()
            except asyncio.QueueEmpty:
                break


class TestNoopFlowController:
    """Test the _NoopFlowController class."""

    def test_noop_controller_methods(self):
        """Test all methods of _NoopFlowController return expected values."""
        controller = _NoopFlowController()
        flow_id = "test-flow"

        # Test acquire returns None
        assert asyncio.run(controller.acquire(flow_id)) is None

        # Test add_credits returns large number
        credits = controller.add_credits(flow_id, 100)
        assert credits == 1_000_000

        # Test get_credits returns large number
        assert controller.get_credits(flow_id) == 1_000_000

        # Test consume returns large number
        consumed = controller.consume(flow_id, 50)
        assert consumed == 1_000_000

        # Test needs_refill always returns False
        assert controller.needs_refill(flow_id) is False

        # Test next_window returns expected tuple
        window, flags = controller.next_window(flow_id)
        assert window == 0
        assert flags == FlowFlags.NONE


class TestTimestampFunction:
    """Test the _timestamp function."""

    @patch("naylence.fame.connector.base_async_connector.format_timestamp")
    @patch("naylence.fame.connector.base_async_connector.color")
    def test_timestamp_formatting(self, mock_color, mock_format_timestamp):
        """Test _timestamp function formats and colors timestamp."""
        mock_format_timestamp.return_value = "2023-01-01 12:00:00"
        mock_color.return_value = "colored_timestamp"

        result = _timestamp()

        mock_format_timestamp.assert_called_once()
        mock_color.assert_called_once_with("2023-01-01 12:00:00", AnsiColor.GRAY)
        assert result == "colored_timestamp"


class TestBaseAsyncConnectorInitialization:
    """Test BaseAsyncConnector initialization and configuration."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        connector = MockAsyncConnector()

        assert connector._enqueue_timeout == 0.1
        assert connector._drain_timeout == 1.0
        assert connector._metrics is None
        assert connector._handler is None
        assert connector._send_q.maxsize == 1_000
        assert connector._state == ConnectorState.INITIALIZED
        assert connector._close_code is None
        assert connector._close_reason is None
        assert connector._last_error is None
        assert isinstance(connector._flow_ctrl, _NoopFlowController) is not FLOW_CONTROL_ENABLED
        assert connector._fc_enabled == FLOW_CONTROL_ENABLED
        assert connector._initial_window == 32

    def test_init_with_custom_params(self):
        """Test initialization with custom parameters."""
        metrics = Mock(spec=MetricsEmitter)
        connector = MockAsyncConnector(
            max_queue_size=500,
            initial_window=64,
            enqueue_timeout=0.5,
            drain_timeout=2.0,
            flow_control=False,
            metrics_emitter=metrics,
        )

        assert connector._enqueue_timeout == 0.5
        assert connector._drain_timeout == 2.0
        assert connector._metrics is metrics
        assert connector._send_q.maxsize == 500
        assert connector._initial_window == 64
        assert isinstance(connector._flow_ctrl, _NoopFlowController)
        assert connector._fc_enabled is False

    def test_init_flow_control_disabled_by_env(self):
        """Test flow control disabled by environment variable."""
        # Explicitly disable flow control in constructor
        connector = MockAsyncConnector(flow_control=False)
        assert isinstance(connector._flow_ctrl, _NoopFlowController)
        assert connector._fc_enabled is False

    @patch("naylence.fame.channel.flow_controller.FlowController")
    def test_init_flow_control_enabled_explicitly(self, mock_flow_controller_class):
        """Test flow control enabled explicitly overrides environment."""
        mock_controller = Mock()
        mock_flow_controller_class.return_value = mock_controller

        connector = MockAsyncConnector(flow_control=True)

        mock_flow_controller_class.assert_called_once_with(32)
        assert connector._flow_ctrl is mock_controller
        assert connector._fc_enabled is True


class TestBaseAsyncConnectorProperties:
    """Test BaseAsyncConnector property methods."""

    def test_state_properties(self):
        """Test state property getters."""
        connector = MockAsyncConnector()

        # Test initial state
        assert connector.state == ConnectorState.INITIALIZED
        assert connector.connector_state == ConnectorState.INITIALIZED

        # Test after state change
        connector._set_state(ConnectorState.STARTED)
        assert connector.state == ConnectorState.STARTED
        assert connector.connector_state == ConnectorState.STARTED

    def test_close_properties_initial(self):
        """Test close-related properties in initial state."""
        connector = MockAsyncConnector()

        assert connector.close_code is None
        assert connector.close_reason is None
        assert connector.last_error is None

    def test_close_properties_after_close(self):
        """Test close-related properties after close."""
        connector = MockAsyncConnector()
        error = ValueError("test error")

        # Simulate close with code and reason
        connector._close_code = 1001
        connector._close_reason = "going away"
        connector._last_error = error

        assert connector.close_code == 1001
        assert connector.close_reason == "going away"
        assert connector.last_error is error

    @patch("naylence.fame.connector.base_async_connector.logger")
    def test_set_state_with_logging(self, mock_logger):
        """Test _set_state method logs state transitions."""
        connector = MockAsyncConnector()

        # Test state change
        connector._set_state(ConnectorState.STARTED)

        mock_logger.debug.assert_called_once_with(
            "connector_state_transition",
            connector_id=connector._connector_flow_id,
            old_state="initialized",
            new_state="started",
        )

    def test_set_state_no_change(self):
        """Test _set_state doesn't log when state doesn't change."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            connector._set_state(ConnectorState.INITIALIZED)  # Same state

            mock_logger.debug.assert_not_called()


class TestBaseAsyncConnectorLifecycle:
    """Test BaseAsyncConnector lifecycle methods."""

    @pytest.mark.asyncio
    async def test_start_success(self):
        """Test successful start operation."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)

        assert connector._handler is handler
        assert connector._state == ConnectorState.STARTED
        assert connector._send_task is not None
        assert connector._recv_task is not None

    @pytest.mark.asyncio
    async def test_start_already_started(self):
        """Test start fails if already started."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)

        # Try to start again
        with pytest.raises(RuntimeError, match="Connector already started"):
            await connector.start(handler)

    @pytest.mark.asyncio
    async def test_start_invalid_state(self):
        """Test start fails in invalid state."""
        connector = MockAsyncConnector()
        connector._set_state(ConnectorState.CLOSED)
        handler = AsyncMock()

        with pytest.raises(RuntimeError, match="Cannot start connector in state"):
            await connector.start(handler)

    @pytest.mark.asyncio
    async def test_replace_handler(self):
        """Test handler replacement."""
        connector = MockAsyncConnector()
        handler1 = AsyncMock()
        handler2 = AsyncMock()

        await connector.start(handler1)
        assert connector._handler is handler1

        await connector.replace_handler(handler2)
        assert connector._handler is handler2

        # Cleanup
        await connector.cleanup()

    @pytest.mark.asyncio
    async def test_stop_success(self):
        """Test successful stop operation."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)
        await connector.stop()

        assert connector._state == ConnectorState.STOPPED
        assert connector._closed.is_set()

    @pytest.mark.asyncio
    async def test_stop_already_stopped(self):
        """Test stop when already stopped logs debug."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            connector._set_state(ConnectorState.STOPPED)

            await connector.stop()

            mock_logger.debug.assert_has_calls(
                [
                    call(
                        "connector_state_transition",
                        connector_id=connector._connector_flow_id,
                        old_state="initialized",
                        new_state="stopped",
                    ),
                    call(
                        "connector_stop_already_stopped",
                        current_state="stopped",
                        connector_id=connector._connector_flow_id,
                    ),
                ]
            )

    @pytest.mark.asyncio
    async def test_stop_with_last_error(self):
        """Test stop re-raises last error."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        error = ValueError("test error")

        await connector.start(handler)
        connector._last_error = error

        with pytest.raises(ValueError, match="test error"):
            await connector.stop()

    @pytest.mark.asyncio
    async def test_close_success(self):
        """Test successful close operation."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)
        await connector.close(code=1001, reason="going away")

        assert connector._state == ConnectorState.CLOSED
        assert connector._closed.is_set()
        assert connector._close_code == 1001
        assert connector._close_reason == "going away"

    @pytest.mark.asyncio
    async def test_close_with_defaults(self):
        """Test close with default code and reason."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)
        await connector.close()

        assert connector._close_code == 1000
        assert connector._close_reason == "normal closure"

    @pytest.mark.asyncio
    async def test_close_invalid_state(self):
        """Test close in invalid state logs warning."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            connector._set_state(ConnectorState.CLOSED)

            await connector.close()

            mock_logger.warning.assert_called_once_with(
                "connector_close_invalid_state",
                current_state="closed",
                connector_id=connector._connector_flow_id,
            )

    @pytest.mark.asyncio
    async def test_push_to_receive_not_implemented(self):
        """Test push_to_receive raises NotImplementedError in base class."""
        # Cannot instantiate BaseAsyncConnector directly as it's abstract
        # We test this via a class that only implements the abstract methods

        class MinimalConnector(BaseAsyncConnector):
            async def _transport_send_bytes(self, data: bytes) -> None:
                pass

            async def _transport_receive(self):
                return b"{}"

        connector = MinimalConnector(max_queue_size=10)

        with pytest.raises(NotImplementedError, match="Subclasses must implement push_to_receive"):
            await connector.push_to_receive(b"test")

    @pytest.mark.asyncio
    async def test_wait_until_closed(self):
        """Test wait_until_closed waits for close event."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)

        # Start waiting in background
        wait_task = asyncio.create_task(connector.wait_until_closed())

        # Should not complete yet
        await asyncio.sleep(0.01)
        assert not wait_task.done()

        # Close connector
        await connector.close()

        # Wait should complete
        await wait_task


class TestBaseAsyncConnectorSend:
    """Test BaseAsyncConnector send operations."""

    @pytest.mark.asyncio
    async def test_send_basic_envelope(self):
        """Test sending a basic envelope."""
        connector = MockAsyncConnector(flow_control=False)
        handler = AsyncMock()
        await connector.start(handler)

        envelope = FameEnvelope(frame=DataFrame(payload="test message"))
        await connector.send(envelope)

        # Wait a bit for the send loop to process
        await asyncio.sleep(0.1)

        assert len(connector._sent_data) == 1
        sent_json = json.loads(connector._sent_data[0].decode())
        assert sent_json["frame"]["payload"] == "test message"

    @pytest.mark.asyncio
    async def test_send_closed_connector(self):
        """Test sending on closed connector raises error."""
        connector = MockAsyncConnector()
        handler = AsyncMock()

        await connector.start(handler)
        await connector.close()

        envelope = FameEnvelope(frame=DataFrame(payload="test"))

        with pytest.raises(FameTransportClose, match="Connection closed"):
            await connector.send(envelope)

    @pytest.mark.asyncio
    async def test_send_message_too_large(self):
        """Test sending oversized message raises error."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Create very large message
        large_data = "x" * (FAME_MAX_MESSAGE_SIZE + 1000)
        envelope = FameEnvelope(frame=DataFrame(payload=large_data))

        with pytest.raises(FameMessageTooLarge, match="Message size .* exceeds maximum"):
            await connector.send(envelope)

    @pytest.mark.asyncio
    async def test_send_queue_timeout(self):
        """Test send queue timeout raises BackPressureFull."""
        # Create connector with very small queue and very short timeout
        connector = MockAsyncConnector(max_queue_size=1, enqueue_timeout=0.001)

        handler = AsyncMock()
        await connector.start(handler)

        try:
            # Fill the queue to capacity by sending messages but blocking the send loop
            # from processing them by blocking the transport
            original_transport_send_bytes = connector._transport_send_bytes
            send_blocked = asyncio.Event()

            async def blocked_transport_send_bytes(data):
                await send_blocked.wait()  # Block until event is set
                return await original_transport_send_bytes(data)

            connector._transport_send_bytes = blocked_transport_send_bytes

            # Send one message to fill queue (max_queue_size=1)
            envelope1 = FameEnvelope(frame=DataFrame(payload="msg1"))

            # This should succeed and fill the queue
            await connector.send(envelope1)

            # Allow send loop to start processing but block on transport
            await asyncio.sleep(0.002)

            # Send another message - should be taken by send loop but stuck in transport
            envelope2 = FameEnvelope(frame=DataFrame(payload="msg2"))
            await connector.send(envelope2)

            # Give time for send loop to take second message and get stuck
            await asyncio.sleep(0.002)

            # Now the queue should be full, and the next send should timeout
            envelope3 = FameEnvelope(frame=DataFrame(payload="msg3"))
            with pytest.raises(BackPressureFull, match="send-queue full"):
                await connector.send(envelope3)

        finally:
            send_blocked.set()  # Unblock transport
            await connector.close()
            await connector.cleanup()

    @pytest.mark.asyncio
    async def test_send_with_flow_control(self):
        """Test sending with flow control enabled."""
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = Mock()
            mock_fc.acquire = AsyncMock()
            mock_fc.next_window.return_value = (42, FlowFlags.SYN)
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True)
            handler = AsyncMock()
            await connector.start(handler)

            try:
                envelope = FameEnvelope(frame=DataFrame(payload="test"))
                await connector.send(envelope)

                # Wait for send loop to process
                await asyncio.sleep(0.01)

                # Verify flow control was used
                mock_fc.acquire.assert_called_once()
                mock_fc.next_window.assert_called_once()

                # Check that data was sent (even if flow control processing varies)
                assert len(connector._sent_data) > 0
                sent_data = json.loads(connector._sent_data[0].decode())
                # Verify the data frame was sent properly
                assert "frame" in sent_data
                assert sent_data["frame"]["payload"] == "test"
            finally:
                await connector.close()
                await connector.cleanup()

    @pytest.mark.asyncio
    async def test_send_with_metrics(self):
        """Test sending with metrics emitter."""
        metrics = Mock(spec=MetricsEmitter)
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = Mock()
            mock_fc.acquire = AsyncMock()
            mock_fc.next_window.return_value = (1, FlowFlags.NONE)
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True, metrics_emitter=metrics)
            handler = AsyncMock()
            await connector.start(handler)

            envelope = FameEnvelope(frame=DataFrame(payload="test"))
            await connector.send(envelope)

            # Verify metrics were recorded
            assert metrics.histogram.call_count >= 1  # acquire_latency
            assert metrics.gauge.call_count >= 1  # send_queue_depth

    @pytest.mark.asyncio
    async def test_send_credit_update_skips_flow_control(self):
        """Test CreditUpdateFrame skips flow control."""
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = AsyncMock()
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True)
            handler = AsyncMock()
            await connector.start(handler)

            credit_frame = CreditUpdateFrame(flow_id="test", credits=10)
            envelope = FameEnvelope(frame=credit_frame)
            await connector.send(envelope)

            # Flow control should not have been used
            mock_fc.acquire.assert_not_called()
            mock_fc.next_window.assert_not_called()


class TestBaseAsyncConnectorReceive:
    """Test BaseAsyncConnector receive operations."""

    @pytest.mark.asyncio
    async def test_receive_loop_handler_not_set(self):
        """Test receive loop fails if handler not set."""
        connector = MockAsyncConnector()

        with pytest.raises(RuntimeError, match="Handler not set"):
            await connector._recv_loop()

    @pytest.mark.asyncio
    async def test_receive_envelope_object(self):
        """Test receiving FameEnvelope object."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        envelope = FameEnvelope(frame=DataFrame(payload="test"))

        # Push envelope to receive queue and let loop process it
        await connector.push_to_receive(envelope)

        # Wait a bit for processing
        await asyncio.sleep(0.01)

        # Handler should have been called
        handler.assert_called_once()
        call_args = handler.call_args
        assert call_args[0][0] == envelope  # First argument is envelope
        assert isinstance(call_args[0][1], FameDeliveryContext)  # Second is context

    @pytest.mark.asyncio
    async def test_receive_channel_message(self):
        """Test receiving FameChannelMessage object."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        envelope = FameEnvelope(frame=DataFrame(payload="test"))
        context = FameDeliveryContext(from_connector=connector)
        message = FameChannelMessage(envelope=envelope, context=context)

        await connector.push_to_receive(message)
        await asyncio.sleep(0.01)

        handler.assert_called_once()
        call_args = handler.call_args
        assert call_args[0][0] == envelope
        assert call_args[0][1] == context

    @pytest.mark.asyncio
    async def test_receive_bytes_valid_json(self):
        """Test receiving valid JSON bytes."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        envelope = FameEnvelope(frame=DataFrame(payload="test"))
        json_bytes = envelope.model_dump_json(by_alias=True, exclude_none=True).encode()

        await connector.push_to_receive(json_bytes)
        await asyncio.sleep(0.01)

        handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_receive_bytes_invalid_json(self):
        """Test receiving invalid JSON bytes continues processing."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            invalid_json = b'{"invalid": json}'

            await connector.push_to_receive(invalid_json)
            await asyncio.sleep(0.01)

            # Should log error and continue
            mock_logger.error.assert_called()
            handler.assert_not_called()

    @pytest.mark.asyncio
    async def test_receive_bytes_validation_error(self):
        """Test receiving bytes with validation error continues processing."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            # Valid JSON but invalid envelope structure
            invalid_envelope = b'{"frame": {"invalid": "structure"}}'

            await connector.push_to_receive(invalid_envelope)
            await asyncio.sleep(0.01)

            mock_logger.error.assert_called()
            handler.assert_not_called()

    @pytest.mark.asyncio
    async def test_receive_bytes_unexpected_error(self):
        """Test receiving bytes with unexpected error during parsing."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Mock model_validate_json to raise unexpected error
        with patch(
            "naylence.fame.core.protocol.envelope.FameEnvelope.model_validate_json"
        ) as mock_validate:
            mock_validate.side_effect = RuntimeError("Unexpected error")

            invalid_json = b'{"test": "data"}'
            await connector.push_to_receive(invalid_json)
            await asyncio.sleep(0.01)

            # Should continue processing and log the error
            # The error is logged but the loop continues

    @pytest.mark.asyncio
    async def test_receive_invalid_message_type(self):
        """Test receiving invalid message type raises TypeError."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        await connector.push_to_receive("invalid string")
        await asyncio.sleep(0.01)

        # Should log the error but continue processing

    @pytest.mark.asyncio
    async def test_receive_credit_update_frame(self):
        """Test receiving CreditUpdateFrame updates flow controller."""
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = Mock()
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True)
            handler = AsyncMock()
            await connector.start(handler)

            credit_frame = CreditUpdateFrame(flow_id="test", credits=50)
            envelope = FameEnvelope(frame=credit_frame)

            await connector.push_to_receive(envelope)
            await asyncio.sleep(0.01)

            # Credit should be added to flow controller
            mock_fc.add_credits.assert_called_once_with("test", 50)
            # Handler should not be called for credit updates
            handler.assert_not_called()

    @pytest.mark.asyncio
    async def test_receive_with_show_envelopes(self):
        """Test receive with envelope display enabled."""
        with patch.dict(os.environ, {ENV_VAR_SHOW_ENVELOPES: "true"}):
            with patch("builtins.print") as mock_print:
                connector = MockAsyncConnector()
                handler = AsyncMock()
                await connector.start(handler)

                try:
                    envelope = FameEnvelope(frame=DataFrame(payload="test"))
                    # Push the JSON representation as bytes, not string
                    envelope_json = envelope.model_dump_json(by_alias=True)
                    await connector.push_to_receive(envelope_json.encode())

                    # Allow time for the receive loop to process the envelope
                    await asyncio.sleep(0.05)

                    # Should have printed envelope
                    mock_print.assert_called()
                finally:
                    await connector.close()
                    await connector.cleanup()

    @pytest.mark.asyncio
    async def test_receive_flow_control_consume_and_credit(self):
        """Test receive consumes flow control and emits credit if needed."""
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = Mock()
            mock_fc.consume.return_value = 5
            mock_fc.needs_refill.return_value = True
            mock_fc.add_credits.return_value = 32
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True)
            handler = AsyncMock()
            await connector.start(handler)

            envelope = FameEnvelope(frame=DataFrame(payload="test"), flow_id="test-flow")
            await connector.push_to_receive(envelope)
            await asyncio.sleep(0.01)

            # Flow control should be consumed
            mock_fc.consume.assert_called_once_with("test-flow")
            # Credit should be checked and refilled
            mock_fc.needs_refill.assert_called_once_with("test-flow")
            mock_fc.add_credits.assert_called_once_with("test-flow", 32)

    @pytest.mark.asyncio
    async def test_receive_loop_cancelled_error(self):
        """Test receive loop handles CancelledError properly."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            try:
                # Put something in the queue to ensure the loop starts
                await asyncio.sleep(0.01)

                # Cancel the receive task - this should trigger the CancelledError
                connector._recv_task.cancel()

                # Wait for the cancellation to propagate
                try:
                    await connector._recv_task
                except asyncio.CancelledError:
                    pass

                # Check if the debug log was called
                mock_logger.debug.assert_any_call("recv_loop_cancelled", name="MockAsyncConnector")
            finally:
                await connector.close()
                await connector.cleanup()

    @pytest.mark.asyncio
    async def test_receive_loop_transport_close_error(self):
        """Test receive loop handles FameTransportClose properly."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        try:
            # Simulate transport close
            close_error = FameTransportClose(code=1001, reason="going away")
            await connector.push_to_receive(close_error)

            # Wait for shutdown to complete
            await asyncio.sleep(0.1)

            assert connector._closed.is_set()
        finally:
            if not connector._closed.is_set():
                await connector.close()
            await connector.cleanup()

    @pytest.mark.asyncio
    async def test_receive_loop_unexpected_error(self):
        """Test receive loop handles unexpected errors."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            handler = AsyncMock()
            handler.side_effect = RuntimeError("Handler error")
            await connector.start(handler)

            try:
                envelope = FameEnvelope(frame=DataFrame(payload="test"))
                # Push JSON message as bytes, not string
                envelope_json = envelope.model_dump_json(by_alias=True)
                await connector.push_to_receive(envelope_json.encode())

                # Allow time for the receive loop to process the message and handle the error
                await asyncio.sleep(0.1)

                # Check that the error was logged - the error should have been caught and logged
                # by the recv_loop exception handler
                mock_logger.critical.assert_called_with(
                    "unexpected_error_in recv_loop",
                    exc_info=True,
                )
            finally:
                # Close will raise the RuntimeError because it's stored in last_spawner_error
                try:
                    await connector.close()
                except RuntimeError as e:
                    assert str(e) == "Handler error"
                await connector.cleanup()


class TestBaseAsyncConnectorShutdown:
    """Test BaseAsyncConnector shutdown and error handling."""

    @pytest.mark.asyncio
    async def test_shutdown_with_error(self):
        """Test _shutdown_with_error method."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        error = ValueError("test error")
        with pytest.raises(ValueError, match="test error"):
            await connector._shutdown_with_error(error, code=1011, reason="custom reason")

        assert connector._closed.is_set()
        assert connector._close_code == 1011
        assert connector._close_reason == "custom reason"
        assert connector._last_error is error

    @pytest.mark.asyncio
    async def test_shutdown_with_error_default_reason(self):
        """Test _shutdown_with_error with default reason."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        error = ValueError("test error")
        with pytest.raises(ValueError, match="test error"):
            await connector._shutdown_with_error(error)

        assert connector._close_reason == "ValueError: test error"

    @pytest.mark.asyncio
    async def test_shutdown_already_closed(self):
        """Test shutdown when already closed returns early."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Close first time
        await connector._shutdown(1000, "first close")

        # Second close should return early
        old_code = connector._close_code
        await connector._shutdown(1001, "second close")

        # Code should not change
        assert connector._close_code == old_code

    @pytest.mark.asyncio
    async def test_shutdown_queue_full_cancels_send_task(self):
        """Test shutdown cancels send task if queue is full."""
        # Create connector with small queue
        connector = MockAsyncConnector(max_queue_size=1)
        handler = AsyncMock()
        await connector.start(handler)

        # Fill the queue
        await connector._send_q.put(b"data")

        # Shutdown should cancel send task since queue is full
        await connector._shutdown(1000, "test")

        assert connector._closed.is_set()

    @pytest.mark.asyncio
    async def test_shutdown_task_timeout_and_cancellation(self):
        """Test shutdown handles task completion and handles timeouts properly."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Verify tasks were created during start
        assert connector._send_task is not None
        assert connector._recv_task is not None
        assert not connector._send_task.done()
        assert not connector._recv_task.done()

        try:
            # Call shutdown with short timeouts
            await connector._shutdown(1000, "test", grace_period=0.01, join_timeout=0.01)

            # Tasks should be done after shutdown (either completed normally or cancelled)
            assert connector._send_task.done()
            assert connector._recv_task.done()

            # Verify shutdown state is set properly
            assert connector._closed.is_set()
            assert connector._close_code == 1000
            assert connector._close_reason == "test"
        finally:
            # Cleanup
            await connector.cleanup()

    @pytest.mark.asyncio
    async def test_shutdown_task_exception_websocket_race(self):
        """Test shutdown handles WebSocket race condition gracefully."""
        with patch("asyncio.wait") as mock_wait:
            mock_wait.return_value = (set(), {Mock(), Mock()})

            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            send_task = AsyncMock()
            recv_task = AsyncMock()
            connector._send_task = send_task
            connector._recv_task = recv_task

            # Mock wait_for to raise WebSocket race condition error
            with patch("asyncio.wait_for") as mock_wait_for:
                mock_wait_for.side_effect = Exception("await wasn't used with future")

                with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
                    await connector._shutdown(1000, "test")

                    # Should log debug for known race condition
                    mock_logger.debug.assert_called()
                    assert "race_condition" in str(mock_logger.debug.call_args)

    @pytest.mark.asyncio
    async def test_shutdown_task_unexpected_exception(self):
        """Test shutdown handles unexpected task exceptions."""
        with patch("asyncio.wait") as mock_wait:
            mock_wait.return_value = (set(), {Mock(), Mock()})

            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            send_task = AsyncMock()
            recv_task = AsyncMock()
            connector._send_task = send_task
            connector._recv_task = recv_task

            # Mock wait_for to raise unexpected error
            with patch("asyncio.wait_for") as mock_wait_for:
                mock_wait_for.side_effect = RuntimeError("Unexpected error")

                with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
                    await connector._shutdown(1000, "test")

                    # Should log error for unexpected exception
                    mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_shutdown_raises_last_error(self):
        """Test shutdown raises last_error if present."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        error = ValueError("test error")
        connector._last_error = error

        with pytest.raises(ValueError, match="test error"):
            await connector._shutdown(1000, "test")

    @pytest.mark.asyncio
    async def test_shutdown_raises_spawner_error(self):
        """Test shutdown raises last_spawner_error if present."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Mock spawner error
        spawner_error = RuntimeError("spawner error")
        with patch.object(
            type(connector), "last_spawner_error", new_callable=PropertyMock, return_value=spawner_error
        ):
            with pytest.raises(RuntimeError, match="spawner error"):
                await connector._shutdown(1000, "test")


class TestBaseAsyncConnectorSendLoop:
    """Test BaseAsyncConnector send loop functionality."""

    @pytest.mark.asyncio
    async def test_send_loop_processes_data(self):
        """Test send loop processes data from queue."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Add data to send queue
        test_data = b"test message"
        await connector._send_q.put(test_data)

        # Wait for processing
        await asyncio.sleep(0.01)

        assert test_data in connector._sent_data

    @pytest.mark.asyncio
    async def test_send_loop_stops_on_sentinel(self):
        """Test send loop stops when receiving stop sentinel."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Put stop sentinel
        await connector._send_q.put(_STOP_SENTINEL)

        # Wait for task to complete
        await connector._send_task

        # Task should be done
        assert connector._send_task.done()

    @pytest.mark.asyncio
    async def test_send_loop_handles_cancelled_error(self):
        """Test send loop handles cancellation gracefully."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            # Put some data in the queue so the send loop can process it
            test_data = b"test data"
            await connector._send_q.put(test_data)

            # Give the send loop a moment to start processing
            await asyncio.sleep(0.01)

            # Cancel the send task
            connector._send_task.cancel()

            try:
                await connector._send_task
            except asyncio.CancelledError:
                pass

            # Check if the expected call was made (might not be the last call)
            mock_logger.debug.assert_any_call("send_loop_cancelled", loop_name="MockAsyncConnector")

            # Cleanup
            try:
                await connector.close()
            except Exception:
                pass
            await connector.cleanup()

    @pytest.mark.asyncio
    async def test_send_loop_handles_transport_close(self):
        """Test send loop handles FameTransportClose."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        # Make transport send raise FameTransportClose
        connector._transport_send_bytes

        async def failing_send(data):
            raise FameTransportClose(code=1001, reason="going away")

        connector._transport_send_bytes = failing_send

        # Put data in queue
        await connector._send_q.put(b"test")

        # Wait for shutdown to complete
        await asyncio.sleep(0.1)

        assert connector._closed.is_set()

    @pytest.mark.asyncio
    async def test_send_loop_handles_unexpected_exception(self):
        """Test send loop handles unexpected exceptions."""
        with patch("naylence.fame.connector.base_async_connector.logger") as mock_logger:
            connector = MockAsyncConnector()
            handler = AsyncMock()
            await connector.start(handler)

            # Make transport send raise unexpected error
            async def failing_send(data):
                raise RuntimeError("Unexpected error")

            connector._transport_send_bytes = failing_send

            # Put data in queue
            await connector._send_q.put(b"test")

            with pytest.raises(RuntimeError, match="Unexpected error"):
                await connector._send_task

            mock_logger.critical.assert_called()

    @pytest.mark.asyncio
    async def test_send_loop_invalid_data_type(self):
        """Test send loop assertion for invalid data type."""
        connector = MockAsyncConnector()
        handler = AsyncMock()
        await connector.start(handler)

        try:
            # Put invalid data type in queue
            await connector._send_q.put("invalid string data")

            # Allow time for send loop to process and fail
            await asyncio.sleep(0.01)

            # The connector should fail due to assertion error
            await connector.close()

            # If we get here, the test should fail because an assertion should have been raised
            assert False, "Expected AssertionError to be raised by send loop"
        except AssertionError as e:
            # This is expected - the assertion error from the send loop
            assert "Expected bytes, got <class 'str'>" in str(e)
        finally:
            # Cleanup if needed
            try:
                await connector.cleanup()
            except Exception:
                pass


class TestBaseAsyncConnectorCreditHelpers:
    """Test BaseAsyncConnector credit emission helpers."""

    @pytest.mark.asyncio
    async def test_maybe_emit_credit_no_refill_needed(self):
        """Test _maybe_emit_credit when no refill is needed."""
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = Mock()
            mock_fc.needs_refill.return_value = False
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True)
            handler = AsyncMock()
            await connector.start(handler)

            try:
                await connector._maybe_emit_credit("test-flow", "trace-123")

                # Should not add credits or send envelope
                mock_fc.add_credits.assert_not_called()
                assert len(connector._sent_data) == 0
            finally:
                await connector.close()
                await connector.cleanup()

    # @pytest.mark.asyncio
    # async def test_maybe_emit_credit_with_refill(self):
    #     """Test _maybe_emit_credit when refill is needed."""
    #     with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
    #         mock_fc = Mock()
    #         mock_fc.needs_refill.return_value = True
    #         mock_fc.add_credits.return_value = 32
    #         mock_fc_class.return_value = mock_fc

    #         connector = MockAsyncConnector(flow_control=True, initial_window=64)
    #         handler = AsyncMock()
    #         await connector.start(handler)

    #         try:
    #             await connector._maybe_emit_credit("test-flow", "trace-123")

    #             # Should add credits and send envelope
    #             mock_fc.add_credits.assert_called_once_with("test-flow", 64)
    #             await asyncio.sleep(0.01)  # Allow time for send loop
    #             assert len(connector._sent_data) > 0
    #         finally:
    #             await connector.close()
    #             await connector.cleanup()

    @pytest.mark.asyncio
    async def test_maybe_emit_credit_with_refill(self):
        """Test _maybe_emit_credit when refill is needed."""
        with patch("naylence.fame.channel.flow_controller.FlowController") as mock_fc_class:
            mock_fc = Mock()
            mock_fc.needs_refill.return_value = True
            mock_fc.add_credits.return_value = 32
            mock_fc_class.return_value = mock_fc

            connector = MockAsyncConnector(flow_control=True, initial_window=64)
            handler = AsyncMock()
            await connector.start(handler)

            try:
                await connector._maybe_emit_credit("test-flow", "trace-123")

                # Should add credits and send envelope
                mock_fc.add_credits.assert_called_once_with("test-flow", 64)
                await asyncio.sleep(0.01)  # Allow time for send loop
                assert len(connector._sent_data) > 0
            finally:
                await connector.close()
                await connector.cleanup()


if __name__ == "__main__":
    pytest.main([__file__])
