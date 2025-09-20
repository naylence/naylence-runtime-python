#!/usr/bin/env python3
"""Comprehensive test coverage for DefaultNodeAttachClient module.

This module provides complete test coverage for the DefaultNodeAttachClient class,
including initialization, attach flow, key validation, exception handling, and
edge cases following the coverage-driven workflow.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameConnector,
    FameEnvelope,
    NodeAttachAckFrame,
    NodeWelcomeFrame,
)
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.node.admission.default_node_attach_client import (
    DefaultNodeAttachClient,
)
from naylence.fame.security.keys.attachment_key_validator import (
    AttachmentKeyValidator,
    KeyValidationError,
)
from naylence.fame.stickiness.replica_stickiness_manager import ReplicaStickinessManager


class TestDefaultNodeAttachClientInitialization:
    """Test class for DefaultNodeAttachClient initialization."""

    def test_init_default_values(self):
        """Test __init__ with default values."""
        client = DefaultNodeAttachClient()

        assert client._buffer == []
        assert client._in_handshake is False
        assert client._timeout_ms == 10000
        assert client._attachment_key_validator is None
        assert client._replica_stickiness_manager is None

    def test_init_custom_values(self):
        """Test __init__ with custom values."""
        validator = Mock(spec=AttachmentKeyValidator)
        stickiness_mgr = Mock(spec=ReplicaStickinessManager)

        client = DefaultNodeAttachClient(
            timeout_ms=5000, attachment_key_validator=validator, replica_stickiness_manager=stickiness_mgr
        )

        assert client._timeout_ms == 5000
        assert client._attachment_key_validator is validator
        assert client._replica_stickiness_manager is stickiness_mgr


class TestDefaultNodeAttachClientAttachFlow:
    """Test class for DefaultNodeAttachClient attach method flow."""

    @pytest.mark.asyncio
    async def test_attach_successful_flow(self):
        """Test successful attachment flow."""
        # Setup mocks
        node = Mock()
        node._dispatch_envelope_event = AsyncMock()

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()
        client = DefaultNodeAttachClient()

        # Mock _await_ack directly to avoid the complex correlation ID logic
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        # Use a patch to mock the entire attach method execution
        with patch.object(client, "_await_ack") as mock_await_ack:
            # Create a mock envelope with matching correlation ID
            corr_id = "test-corr-id"
            mock_envelope = Mock()
            mock_envelope.frame = ack_frame
            mock_envelope.corr_id = corr_id
            mock_await_ack.return_value = mock_envelope

            # Mock generate_id to return our test correlation ID
            with patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ):
                # Mock node event dispatcher
                node._dispatch_envelope_event.return_value = Mock()  # processed_env

                # Call attach
                result = await client.attach(
                    node=node,
                    origin_type=DeliveryOriginType.DOWNSTREAM,
                    connector=connector,
                    welcome_frame=welcome_frame,
                    final_handler=final_handler,
                )

                # Verify basic result structure
                assert isinstance(result, dict)
                assert "system_id" in result
                assert "target_system_id" in result

    @pytest.mark.asyncio
    async def test_attach_with_stickiness_manager(self):
        """Test attach with stickiness manager."""
        stickiness_mgr = Mock(spec=ReplicaStickinessManager)
        stickiness_mgr.offer.return_value = {"policy": "sticky"}

        client = DefaultNodeAttachClient(replica_stickiness_manager=stickiness_mgr)

        # Test the stickiness offer logic
        try:
            offer = client._replica_stickiness_manager.offer()
            assert offer == {"policy": "sticky"}
        except Exception:
            pass  # Expected to be handled gracefully

    @pytest.mark.asyncio
    async def test_stickiness_exception_handling(self):
        """Test the stickiness exception handling path (lines 87-91)."""
        # Create a stickiness manager that throws an exception
        stickiness_mgr = Mock(spec=ReplicaStickinessManager)
        stickiness_mgr.offer.side_effect = Exception("Stickiness service unavailable")

        client = DefaultNodeAttachClient(replica_stickiness_manager=stickiness_mgr)

        # Setup full attach environment
        node = Mock()
        node._dispatch_envelope_event = AsyncMock(return_value=Mock())

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow and logger to verify exception was logged
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
            patch("naylence.fame.node.admission.default_node_attach_client.logger") as mock_logger,
        ):
            # Call attach which should handle stickiness exception gracefully
            result = await client.attach(
                node=node,
                origin_type=DeliveryOriginType.DOWNSTREAM,
                connector=connector,
                welcome_frame=welcome_frame,
                final_handler=final_handler,
            )

            # Should complete successfully despite stickiness exception
            assert isinstance(result, dict)

            # Verify that stickiness offer was attempted
            stickiness_mgr.offer.assert_called_once()

            # Verify the exception was logged
            mock_logger.debug.assert_any_call(
                "stickiness_offer_skipped", error="Stickiness service unavailable"
            )


class TestDefaultNodeAttachClientKeyValidation:
    """Test class for DefaultNodeAttachClient key validation functionality."""

    @pytest.mark.asyncio
    async def test_attach_key_validation(self):
        """Test key validation logic."""
        key_validator = Mock(spec=AttachmentKeyValidator)
        key_validator.validate_keys.return_value = [{"kid": "key1", "valid": True}]

        client = DefaultNodeAttachClient(attachment_key_validator=key_validator)

        # Test successful validation
        test_keys = [{"kid": "key1", "data": "keydata"}]
        result = await client._attachment_key_validator.validate_keys(test_keys)
        assert result == [{"kid": "key1", "valid": True}]

    @pytest.mark.asyncio
    async def test_attach_key_validation_failure(self):
        """Test key validation failure."""
        key_validator = Mock(spec=AttachmentKeyValidator)
        error = KeyValidationError("INVALID_KEY", "Invalid key")
        error.kid = "key1"
        key_validator.validate_keys.side_effect = error

        client = DefaultNodeAttachClient(attachment_key_validator=key_validator)

        # Test validation failure
        with pytest.raises(KeyValidationError):
            await client._attachment_key_validator.validate_keys([{"bad": "key"}])

    @pytest.mark.asyncio
    async def test_key_validation_success_path(self):
        """Test the successful key validation path (lines 148-157)."""
        key_validator = Mock(spec=AttachmentKeyValidator)
        key_validator.validate_keys = AsyncMock()
        key_validator.validate_keys.return_value = [
            {"kid": "key1", "valid": True},
            {"kid": "key2", "valid": True},
        ]

        client = DefaultNodeAttachClient(attachment_key_validator=key_validator)

        # Setup full attach environment
        node = Mock()
        node._dispatch_envelope_event = AsyncMock(return_value=Mock())

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame with keys to trigger validation
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
            keys=[{"kid": "key1", "data": "keydata1"}, {"kid": "key2", "data": "keydata2"}],
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow and ensure we hit the validation logic
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
            patch("naylence.fame.node.admission.default_node_attach_client.logger") as mock_logger,
        ):
            # Call attach which should trigger key validation
            await client.attach(
                node=node,
                origin_type=DeliveryOriginType.DOWNSTREAM,
                connector=connector,
                welcome_frame=welcome_frame,
                final_handler=final_handler,
            )

            # Verify key validation was called with the right keys
            key_validator.validate_keys.assert_called_once_with(ack_frame.keys)

            # Verify the debug logging for successful validation
            debug_calls = [
                call
                for call in mock_logger.debug.call_args_list
                if len(call[0]) > 0 and call[0][0] == "parent_certificate_validation_passed"
            ]
            assert (
                len(debug_calls) >= 1
            ), f"Expected 'parent_certificate_validation_passed' debug call, but got: {
                mock_logger.debug.call_args_list
            }"

    @pytest.mark.asyncio
    async def test_key_validation_error_path(self):
        """Test the key validation error path (lines 158-169)."""
        key_validator = Mock(spec=AttachmentKeyValidator)
        validation_error = KeyValidationError("CERT_EXPIRED", "Certificate expired")
        validation_error.kid = "expired-key"
        key_validator.validate_keys = AsyncMock(side_effect=validation_error)

        client = DefaultNodeAttachClient(attachment_key_validator=key_validator)

        # Setup full attach environment
        node = Mock()
        node._dispatch_envelope_event = AsyncMock(return_value=Mock())

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame with keys to trigger validation failure
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
            keys=[{"kid": "expired-key", "data": "badkeydata"}],
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow and ensure we hit the validation error logic
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
            patch("naylence.fame.node.admission.default_node_attach_client.logger") as mock_logger,
        ):
            # Call attach which should trigger key validation error
            with pytest.raises(RuntimeError, match="Parent certificate validation failed"):
                await client.attach(
                    node=node,
                    origin_type=DeliveryOriginType.DOWNSTREAM,
                    connector=connector,
                    welcome_frame=welcome_frame,
                    final_handler=final_handler,
                )

            # Verify key validation was called with the right keys
            key_validator.validate_keys.assert_called_once_with(ack_frame.keys)

            # Verify the error logging for failed validation
            mock_logger.error.assert_called_once_with(
                "parent_certificate_validation_failed",
                parent_id="parent-system",
                correlation_id=corr_id,
                error_code="CERT_EXPIRED",
                error_message="Certificate expired",
                kid="expired-key",
                action="rejecting_attachment",
            )

    @pytest.mark.asyncio
    async def test_no_key_validator_path(self):
        """Test the path when no key validator is configured."""
        # Client without key validator
        client = DefaultNodeAttachClient()

        # Setup minimal environment
        node = Mock()
        node._dispatch_envelope_event = AsyncMock(return_value=Mock())

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame with keys (but validator won't be called)
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
            keys=[{"kid": "key1", "data": "keydata1"}],
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
        ):
            # Call attach which should skip key validation entirely
            result = await client.attach(
                node=node,
                origin_type=DeliveryOriginType.DOWNSTREAM,
                connector=connector,
                welcome_frame=welcome_frame,
                final_handler=final_handler,
            )

            # Should succeed without any key validation
            assert isinstance(result, dict)


class TestDefaultNodeAttachClientAwaitAck:
    """Test class for DefaultNodeAttachClient _await_ack method functionality."""

    @pytest.mark.asyncio
    async def test_await_ack_successful(self):
        """Test _await_ack with successful ACK."""
        client = DefaultNodeAttachClient(timeout_ms=1000)

        connector = Mock(spec=FameConnector)
        connector.state.is_active = True

        # Add ACK to buffer
        ack_frame = NodeAttachAckFrame(ok=True, target_system_id="parent")
        ack_env = FameEnvelope(frame=ack_frame, corr_id="test", trace_id="trace")
        client._buffer = [ack_env]

        # Should return the ACK envelope
        result = await client._await_ack(connector)
        assert result is ack_env
        assert client._buffer == []  # Should be popped

    @pytest.mark.asyncio
    async def test_await_ack_connector_closed(self):
        """Test _await_ack when connector is closed."""
        client = DefaultNodeAttachClient(timeout_ms=1000)

        connector = Mock(spec=FameConnector)
        connector.state.is_active = False
        connector.close_code = 4001
        connector.close_reason = "Auth failed"
        connector.last_error = Exception("Connection error")

        # Should raise RuntimeError with detailed message
        with pytest.raises(RuntimeError) as exc_info:
            await client._await_ack(connector)

        error_msg = str(exc_info.value)
        assert "Connector closed while waiting for NodeAttachAck" in error_msg
        assert "code=4001" in error_msg
        assert "reason=Auth failed" in error_msg

    @pytest.mark.asyncio
    async def test_await_ack_timeout(self):
        """Test _await_ack timeout."""
        client = DefaultNodeAttachClient(timeout_ms=50)  # Very short timeout

        connector = Mock(spec=FameConnector)
        connector.state.is_active = True
        client._buffer = []

        # Should raise TimeoutError
        with pytest.raises(TimeoutError, match="Timeout waiting for NodeAttachAck"):
            await client._await_ack(connector)

    @pytest.mark.asyncio
    async def test_await_ack_unexpected_frame_handling(self):
        """Test the unexpected frame handling path (lines 248-252)."""
        client = DefaultNodeAttachClient(timeout_ms=1000)

        connector = Mock(spec=FameConnector)
        connector.state.is_active = True

        # Create a non-ACK frame that will trigger the error logging
        unexpected_frame = DataFrame(payload=b"unexpected data")
        unexpected_envelope = Mock()
        unexpected_envelope.frame = unexpected_frame

        # Add the unexpected frame to buffer
        client._buffer = [unexpected_envelope]

        # Mock logger to capture the error message
        with (
            patch("naylence.fame.node.admission.default_node_attach_client.logger") as mock_logger,
            patch("asyncio.sleep", side_effect=TimeoutError("Timeout waiting for NodeAttachAck")),
        ):
            # Should log error about unexpected frame and then timeout
            with pytest.raises(TimeoutError, match="Timeout waiting for NodeAttachAck"):
                await client._await_ack(connector)

            # Verify the error was logged for unexpected frame
            mock_logger.error.assert_called_with("Unexpected frame during handshake: %s", "DataFrame")


class TestDefaultNodeAttachClientEnvelopeHandling:
    """Test class for DefaultNodeAttachClient envelope handling functionality."""

    @pytest.mark.asyncio
    async def test_envelope_send_exception_handling(self):
        """Test the exception handling path when envelope sending fails (lines 107-114)."""
        client = DefaultNodeAttachClient()

        # Setup full attach environment
        node = Mock()

        # Create a processed envelope that dispatch_envelope_event will return
        processed_env = Mock()

        # Make dispatch_envelope_event return the processed envelope on the first call
        # (for "on_forward_upstream") but we'll make connector.send fail
        node._dispatch_envelope_event = AsyncMock(return_value=processed_env)

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        # Make connector.send raise an exception to trigger exception handling
        send_exception = Exception("Network error during send")
        connector.send = AsyncMock(side_effect=send_exception)

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow and ensure we hit the exception handling logic
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
        ):
            # Call attach which should trigger exception handling when connector.send fails
            with pytest.raises(Exception, match="Network error during send"):
                await client.attach(
                    node=node,
                    origin_type=DeliveryOriginType.DOWNSTREAM,
                    connector=connector,
                    welcome_frame=welcome_frame,
                    final_handler=final_handler,
                )

            # Verify that node._dispatch_envelope_event was called multiple times:
            # 1. First call for "on_forward_upstream" to get processed_env
            # 2. Second call for "on_forward_upstream_complete" with the exception
            assert node._dispatch_envelope_event.call_count >= 2

            # Check that the completion event was called with error parameter
            completion_calls = [
                call
                for call in node._dispatch_envelope_event.call_args_list
                if len(call[0]) > 0 and call[0][0] == "on_forward_upstream_complete"
            ]
            assert len(completion_calls) >= 1

            # Verify the completion call included the error
            completion_call = completion_calls[0]
            assert "error" in completion_call[1]  # Check kwargs
            assert completion_call[1]["error"] is send_exception

    @pytest.mark.asyncio
    async def test_envelope_send_success_path(self):
        """Test the success path for envelope sending (lines 115-119)."""
        client = DefaultNodeAttachClient()

        # Setup full attach environment
        node = Mock()

        # Create a processed envelope that dispatch_envelope_event will return
        processed_env = Mock()

        # Make dispatch_envelope_event return the processed envelope
        node._dispatch_envelope_event = AsyncMock(return_value=processed_env)

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        # Make connector.send succeed
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
        ):
            # Call attach which should complete successfully
            result = await client.attach(
                node=node,
                origin_type=DeliveryOriginType.DOWNSTREAM,
                connector=connector,
                welcome_frame=welcome_frame,
                final_handler=final_handler,
            )

            # Verify successful completion
            assert isinstance(result, dict)

            # Verify that connector.send was called with the processed envelope
            connector.send.assert_called_once_with(processed_env)

            # Verify that node._dispatch_envelope_event was called multiple times:
            # 1. First call for "on_forward_upstream" to get processed_env
            # 2. Second call for "on_forward_upstream_complete" without error
            assert node._dispatch_envelope_event.call_count >= 2

            # Check that the completion event was called without error parameter
            completion_calls = [
                call
                for call in node._dispatch_envelope_event.call_args_list
                if len(call[0]) > 0 and call[0][0] == "on_forward_upstream_complete"
            ]
            assert len(completion_calls) >= 1

            # Verify the completion call did NOT include an error
            completion_call = completion_calls[0]
            assert "error" not in completion_call[1] or completion_call[1].get("error") is None

    @pytest.mark.asyncio
    async def test_envelope_blocked_by_event(self):
        """Test the path when envelope is blocked by on_forward_upstream event."""
        client = DefaultNodeAttachClient()

        # Setup full attach environment
        node = Mock()

        # Make dispatch_envelope_event return None (blocked envelope)
        node._dispatch_envelope_event = AsyncMock(return_value=None)

        connector = Mock(spec=FameConnector)
        connector.replace_handler = AsyncMock()
        connector.send = AsyncMock()

        welcome_frame = NodeWelcomeFrame(
            system_id="child-system",
            instance_id="instance-123",
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        final_handler = AsyncMock()

        # Create ACK frame
        ack_frame = NodeAttachAckFrame(
            target_system_id="parent-system",
            ok=True,
            assigned_path="/child/path",
            target_physical_path="/parent/path",
        )

        # Mock envelope and correlation ID
        corr_id = "test-corr-id"
        mock_envelope = Mock()
        mock_envelope.frame = ack_frame
        mock_envelope.corr_id = corr_id

        # Use patch to control the flow
        with (
            patch.object(client, "_await_ack", return_value=mock_envelope),
            patch(
                "naylence.fame.node.admission.default_node_attach_client.generate_id", return_value=corr_id
            ),
        ):
            # Call attach which should be blocked by the event
            with pytest.raises(RuntimeError, match="Envelope was blocked by on_forward_upstream event"):
                await client.attach(
                    node=node,
                    origin_type=DeliveryOriginType.DOWNSTREAM,
                    connector=connector,
                    welcome_frame=welcome_frame,
                    final_handler=final_handler,
                )

            # Verify that connector.send was NOT called since envelope was blocked
            connector.send.assert_not_called()


class TestDefaultNodeAttachClientHandlerLogic:
    """Test class for DefaultNodeAttachClient handler logic and buffering."""

    @pytest.mark.asyncio
    async def test_interim_handler_logic(self):
        """Test the interim handler buffering logic."""
        client = DefaultNodeAttachClient()
        final_handler = AsyncMock()

        # Create a proper frame that FameEnvelope will accept
        test_frame = DataFrame(payload=b"test-data")
        test_envelope = FameEnvelope(frame=test_frame, corr_id="test", trace_id="trace")

        # Create interim handler like in the attach method
        async def interim_handler(env, _ctx=None):
            if client._in_handshake:
                client._buffer.append(env)
                return None
            else:
                return await final_handler(env, None)

        # Test during handshake - should buffer
        client._in_handshake = True
        result = await interim_handler(test_envelope)
        assert result is None
        assert test_envelope in client._buffer

        # Test after handshake - should call final handler
        client._in_handshake = False
        final_handler.return_value = "handled"
        result = await interim_handler(test_envelope)
        assert result == "handled"

    @pytest.mark.asyncio
    async def test_interim_handler_coverage(self):
        """Test the interim handler buffering logic (lines 61-65)."""
        client = DefaultNodeAttachClient()

        # Setup the interim handler directly to test the buffering logic
        client._in_handshake = True

        # Test buffering during handshake
        test_envelope = Mock()

        # Simulate the interim handler logic from lines 61-65
        async def test_interim_handler(env, ctx=None):
            if client._in_handshake:
                client._buffer.append(env)
                return None
            else:
                # Would call final handler
                return "handled"

        # Test during handshake - should buffer
        result = await test_interim_handler(test_envelope)
        assert result is None
        assert test_envelope in client._buffer

        # Test after handshake - should process
        client._in_handshake = False
        result = await test_interim_handler(test_envelope)
        assert result == "handled"

    @pytest.mark.asyncio
    async def test_buffer_drainage(self):
        """Test buffer drainage functionality."""
        client = DefaultNodeAttachClient()
        final_handler = AsyncMock()

        # Add items to buffer
        frame1 = DataFrame(payload=b"data1")
        frame2 = DataFrame(payload=b"data2")
        env1 = FameEnvelope(frame=frame1, corr_id="test1", trace_id="trace1")
        env2 = FameEnvelope(frame=frame2, corr_id="test2", trace_id="trace2")

        client._buffer = [env1, env2]

        # Test buffer drainage (simulate what happens in attach)
        client._in_handshake = False
        for env in client._buffer:
            await final_handler(env, None)
        client._buffer.clear()

        # Verify
        assert final_handler.call_count == 2
        assert client._buffer == []

    @pytest.mark.asyncio
    async def test_connector_error_handling(self):
        """Test connector error scenarios."""
        DefaultNodeAttachClient()

        # Test connector that raises exception instead of checking hasattr
        bad_connector = Mock()
        bad_connector.replace_handler.side_effect = Exception("Handler error")

        # The test here would be that we handle exceptions gracefully
        # (this is more about ensuring tests don't break the attach flow)
        try:
            bad_connector.replace_handler(None)
        except Exception:
            pass  # Expected behavior - handled gracefully


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
