"""
Comprehensive test coverage for UpstreamSessionManager targeting uncovered lines.

Current coverage: 69.48% (243/322 lines covered)
Target areas:
- Lines 344-364: Key management and crypto provider handling (21 lines)
- Lines 371-385: Ready waiter and FSM task handling (15 lines)
- Lines 508-522: Message pump error handling (15 lines)
- Lines 498-505: Message too large handling (8 lines)
- Lines 597-603: Heartbeat envelope creation (7 lines)
- Lines 632-636: NodeAttachAckFrame filtering (5 lines)

Goal: Achieve 85%+ coverage using systematic testing approach.
"""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.core import (
    DeliveryAckFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameFabric,
    NodeAttachAckFrame,
    NodeHeartbeatAckFrame,
    SecurityContext,
)
from naylence.fame.errors.errors import FameMessageTooLarge, FameTransportClose
from naylence.fame.node.upstream_session_manager import UpstreamSessionManager


class TestUpstreamSessionManagerCoverage:
    """Test class for improving UpstreamSessionManager coverage."""

    @pytest.fixture
    def mock_node(self):
        """Create a mock node with all required attributes."""
        node = Mock()
        node.security_manager = Mock()
        node.security_manager.supports_overlay_security = True
        node.envelope_factory = Mock()
        node._dispatch_envelope_event = AsyncMock()
        node._dispatch_event = AsyncMock()
        return node

    @pytest.fixture
    def session_manager(self, mock_node):
        """Create an UpstreamSessionManager instance for testing."""
        attach_client = Mock()
        return UpstreamSessionManager(
            node=mock_node,
            attach_client=attach_client,
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_welcome=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

    @pytest.mark.asyncio
    async def test_get_keys_no_overlay_security(self, session_manager, mock_node):
        """Test _get_keys when overlay security is not supported."""
        # Target lines 341-342: Early return when overlay security not supported
        mock_node.security_manager.supports_overlay_security = False

        result = session_manager._get_keys()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_keys_no_crypto_provider(self, session_manager):
        """Test _get_keys when crypto provider is not available."""
        # Target lines 344-346: crypto_provider is None
        with patch("naylence.fame.node.upstream_session_manager.get_crypto_provider", return_value=None):
            result = session_manager._get_keys()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_keys_empty_keys(self, session_manager):
        """Test _get_keys when no keys are available."""
        # Target lines 347-364: Empty keys scenario
        mock_crypto_provider = Mock()
        mock_crypto_provider.node_jwk.return_value = None
        mock_crypto_provider.get_jwks.return_value = None

        with patch(
            "naylence.fame.node.upstream_session_manager.get_crypto_provider",
            return_value=mock_crypto_provider,
        ):
            result = session_manager._get_keys()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_keys_with_node_jwk_only(self, session_manager):
        """Test _get_keys with only node_jwk available."""
        # Target lines 350-354: node_jwk path
        mock_crypto_provider = Mock()
        node_jwk = {"kid": "test-key", "use": "sig"}
        mock_crypto_provider.node_jwk.return_value = node_jwk
        mock_crypto_provider.get_jwks.return_value = None

        with patch(
            "naylence.fame.node.upstream_session_manager.get_crypto_provider",
            return_value=mock_crypto_provider,
        ):
            result = session_manager._get_keys()

        assert result == [node_jwk]

    @pytest.mark.asyncio
    async def test_get_keys_with_jwks_filtering(self, session_manager):
        """Test _get_keys with JWKS filtering logic."""
        # Target lines 355-364: JWKS filtering with duplicate key skipping
        mock_crypto_provider = Mock()
        node_jwk = {"kid": "test-key", "use": "sig"}
        jwks = {
            "keys": [
                {"kid": "test-key", "use": "sig"},  # Should be skipped (duplicate)
                {"kid": "test-key", "use": "enc"},  # Should be included (encryption)
                {"kid": "other-key", "use": "sig"},  # Should be included (different kid)
            ]
        }
        mock_crypto_provider.node_jwk.return_value = node_jwk
        mock_crypto_provider.get_jwks.return_value = jwks

        with patch(
            "naylence.fame.node.upstream_session_manager.get_crypto_provider",
            return_value=mock_crypto_provider,
        ):
            result = session_manager._get_keys()

        assert len(result) == 3  # node_jwk + 2 filtered keys
        assert result[0] == node_jwk
        assert {"kid": "test-key", "use": "enc"} in result
        assert {"kid": "other-key", "use": "sig"} in result

    @pytest.mark.asyncio
    async def test_get_keys_empty_jwks_keys(self, session_manager):
        """Test _get_keys when JWKS has no keys."""
        # Target line 357: jwks.get("keys") is empty
        mock_crypto_provider = Mock()
        mock_crypto_provider.node_jwk.return_value = None
        mock_crypto_provider.get_jwks.return_value = {"keys": []}

        with patch(
            "naylence.fame.node.upstream_session_manager.get_crypto_provider",
            return_value=mock_crypto_provider,
        ):
            result = session_manager._get_keys()

        assert result is None

    @pytest.mark.asyncio
    async def test_await_ready_fsm_task_exception(self, session_manager):
        """Test await_ready when FSM task raises an exception."""
        # Target lines 371-385: FSM task exception handling
        session_manager._ready_evt = asyncio.Event()

        # Create a failed FSM task
        failed_task = asyncio.create_task(self._failing_coroutine())
        session_manager._fsm_task = failed_task

        # Wait for the task to fail
        await asyncio.sleep(0.1)

        with pytest.raises(ValueError, match="FSM task failed"):
            await session_manager.await_ready(timeout=0.5)

    async def _failing_coroutine(self):
        """Helper coroutine that raises an exception."""
        await asyncio.sleep(0.05)
        raise ValueError("FSM task failed")

    @pytest.mark.asyncio
    async def test_await_ready_timeout_with_running_fsm(self, session_manager):
        """Test await_ready timeout with running FSM task."""
        # Target lines 371-385: Timeout scenario with running FSM
        session_manager._ready_evt = asyncio.Event()

        # Create a long-running FSM task that doesn't fail
        long_running_task = asyncio.create_task(asyncio.sleep(10))
        session_manager._fsm_task = long_running_task

        try:
            # This should timeout without raising an exception from the FSM task
            await session_manager.await_ready(timeout=0.1)
        finally:
            long_running_task.cancel()

    @pytest.mark.asyncio
    async def test_handle_message_too_large_with_nack(self, session_manager, mock_node):
        """Test _handle_message_too_large with NACK sending."""
        # Target lines 508-522: Message too large NACK handling
        env = Mock()
        env.corr_id = "test-corr-id"
        env.reply_to = "test-destination"
        env.id = "test-env-id"

        mock_fabric = Mock()
        mock_fabric.send = AsyncMock()

        nack_envelope = Mock()
        mock_node.envelope_factory.create_envelope.return_value = nack_envelope

        with patch.object(FameFabric, "current", return_value=mock_fabric):
            await session_manager._handle_message_too_large(env, "Message too large")

        # Verify NACK was created and sent
        mock_node.envelope_factory.create_envelope.assert_called_once()
        call_args = mock_node.envelope_factory.create_envelope.call_args
        assert call_args[1]["to"] == "test-destination"
        assert call_args[1]["corr_id"] == "test-corr-id"
        assert isinstance(call_args[1]["frame"], DeliveryAckFrame)
        assert call_args[1]["frame"].ok is False
        assert call_args[1]["frame"].ref_id == "test-env-id"
        assert call_args[1]["frame"].code == "MESSAGE_TOO_LARGE"

        mock_fabric.send.assert_called_once_with(nack_envelope)

    @pytest.mark.asyncio
    async def test_handle_message_too_large_no_nack_info(self, session_manager):
        """Test _handle_message_too_large without NACK information."""
        # Target early return in _handle_message_too_large
        env = Mock()
        env.corr_id = None  # No correlation ID
        env.reply_to = "test-destination"

        # Should return early without creating NACK
        await session_manager._handle_message_too_large(env, "Message too large")

        # No assertions needed - just ensuring no exception is raised

    @pytest.mark.asyncio
    async def test_message_pump_loop_too_large_exception(self, session_manager):
        """Test message pump loop handling FameMessageTooLarge exception."""
        # Target lines 498-505: FameMessageTooLarge handling in message pump
        session_manager._message_queue = asyncio.Queue()
        session_manager._stop_evt = asyncio.Event()
        session_manager._handle_message_too_large = AsyncMock()

        # Create mock envelope and connector
        env = Mock()
        connector = Mock()
        connector.send = AsyncMock(side_effect=FameMessageTooLarge("Message too large"))

        # Put envelope in queue and stop event after short delay
        await session_manager._message_queue.put(env)
        asyncio.create_task(self._set_stop_after_delay(session_manager._stop_evt, 0.1))

        await session_manager._message_pump_loop(connector, session_manager._stop_evt)

        # Verify the too large handler was called
        session_manager._handle_message_too_large.assert_called_once_with(env, "Message too large")

    @pytest.mark.asyncio
    async def test_message_pump_loop_transport_close_exception(self, session_manager):
        """Test message pump loop handling FameTransportClose exception."""
        # Target lines 502-505: FameTransportClose handling in message pump
        session_manager._message_queue = asyncio.Queue()
        stop_evt = asyncio.Event()

        # Create mock envelope and connector
        env = Mock()
        connector = Mock()
        connector.send = AsyncMock(side_effect=FameTransportClose("Transport closed"))

        # Put envelope in queue
        await session_manager._message_queue.put(env)

        # Should re-raise FameTransportClose
        with pytest.raises(FameTransportClose):
            await session_manager._message_pump_loop(connector, stop_evt)

        # Verify envelope was put back in queue
        assert session_manager._message_queue.qsize() == 1

    async def _set_stop_after_delay(self, stop_evt, delay):
        """Helper to set stop event after delay."""
        await asyncio.sleep(delay)
        stop_evt.set()

    @pytest.mark.asyncio
    async def test_make_heartbeat_enabled_handler_heartbeat_ack(self, session_manager, mock_node):
        """Test heartbeat-enabled handler for NodeHeartbeatAckFrame."""
        # Target lines 597-603: Heartbeat ACK handling
        downstream = AsyncMock()
        handler = session_manager._make_heartbeat_enabled_handler(downstream)

        # Create heartbeat ACK envelope
        env = Mock()
        env.frame = NodeHeartbeatAckFrame()
        context = Mock()

        result = await handler(env, context)

        # Should return None (not call downstream)
        assert result is None
        downstream.assert_not_called()

    @pytest.mark.asyncio
    async def test_make_heartbeat_enabled_handler_attach_ack(self, session_manager, mock_node):
        """Test heartbeat-enabled handler for NodeAttachAckFrame."""
        # Target lines 632-636: NodeAttachAckFrame filtering
        downstream = AsyncMock()
        handler = session_manager._make_heartbeat_enabled_handler(downstream)

        # Create attach ACK envelope
        env = Mock()
        env.frame = NodeAttachAckFrame()
        context = Mock()

        result = await handler(env, context)

        # Should return None (not call downstream)
        assert result is None
        downstream.assert_not_called()

    @pytest.mark.asyncio
    async def test_make_heartbeat_enabled_handler_normal_traffic(self, session_manager, mock_node):
        """Test heartbeat-enabled handler for normal application traffic."""
        # Target line 639: Normal traffic forwarding
        downstream = AsyncMock(return_value="downstream_result")
        handler = session_manager._make_heartbeat_enabled_handler(downstream)

        # Create normal envelope (not heartbeat or attach ACK)
        env = Mock()
        env.frame = Mock()  # Some other frame type
        context = Mock()

        result = await handler(env, context)

        # Should call downstream and return result
        assert result == "downstream_result"
        downstream.assert_called_once_with(env, context)

    @pytest.mark.asyncio
    async def test_make_heartbeat_enabled_handler_security_context_setup(self, session_manager, mock_node):
        """Test heartbeat-enabled handler security context setup."""
        # Target various context setup lines
        downstream = AsyncMock()
        handler = session_manager._make_heartbeat_enabled_handler(downstream)

        session_manager._connector = Mock()
        session_manager._target_system_id = "test-system"
        session_manager._inbound_origin_type = DeliveryOriginType.UPSTREAM

        # Create envelope with context that needs security setup
        env = Mock()
        env.frame = Mock()  # Normal frame
        context = FameDeliveryContext()
        context.security = None  # Will be created

        await handler(env, context)

        # Verify context was set up properly
        assert context.origin_type == DeliveryOriginType.UPSTREAM
        assert context.from_connector == session_manager._connector
        assert context.from_system_id == "test-system"
        assert context.security is not None
        assert context.security.authorization == session_manager._connector.authorization_context

        # Verify dispatch event was called
        mock_node._dispatch_envelope_event.assert_called_once_with(
            "on_envelope_received", mock_node, env, context
        )

    @pytest.mark.asyncio
    async def test_make_heartbeat_enabled_handler_existing_security_context(
        self, session_manager, mock_node
    ):
        """Test heartbeat-enabled handler with existing security context."""
        downstream = AsyncMock()
        handler = session_manager._make_heartbeat_enabled_handler(downstream)

        # Create envelope with existing security context
        env = Mock()
        env.frame = Mock()
        context = FameDeliveryContext()
        existing_security = SecurityContext()
        existing_auth = Mock()
        existing_security.authorization = existing_auth
        context.security = existing_security

        await handler(env, context)

        # Should not override existing authorization
        assert context.security.authorization == existing_auth
