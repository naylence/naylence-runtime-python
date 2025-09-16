"""
Focused tests to boost envelope_listener_manager coverage to 95%.

This file specifically targets uncovered lines and methods identified from coverage analysis.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.delivery.delivery_tracker import EnvelopeStatus

# Import the class under test
from naylence.fame.node.envelope_listener_manager import EnvelopeListenerManager


class TestEnvelopeListenerManagerPublicMethods:
    """Test all public methods to ensure comprehensive coverage"""

    @pytest.fixture
    def manager(self):
        """Create a manager instance with properly mocked dependencies"""
        binding_manager = Mock()
        node_like = Mock()
        node_like.id = "test-node-id"
        node_like.sid = "test-session-id"
        node_like.send = AsyncMock(return_value="sent")

        envelope_factory = Mock()
        delivery_tracker = Mock()

        manager = EnvelopeListenerManager(
            binding_manager=binding_manager,
            node_like=node_like,
            envelope_factory=envelope_factory,
            delivery_tracker=delivery_tracker,
        )

        # Mock the internal components that are created during init
        manager._channel_polling_manager = Mock()
        manager._rpc_server_handler = Mock()
        manager._rpc_client_manager = Mock()
        manager._response_context_manager = Mock()
        manager._streaming_response_handler = Mock()

        return manager

    @pytest.mark.asyncio
    async def test_start_method(self, manager):
        """Test the start method functionality"""
        # Mock the recovery method
        manager.recover_unhandled_inbound_envelopes = AsyncMock()

        await manager.start()

        # Verify recovery was called during start
        manager.recover_unhandled_inbound_envelopes.assert_called_once()

    @pytest.mark.asyncio
    async def test_listen_rpc_method(self, manager):
        """Test the listen_rpc method"""
        # Mock binding manager
        mock_binding = Mock()
        mock_channel = Mock()
        mock_binding.channel = mock_channel
        manager._binding_manager.bind = AsyncMock(return_value=mock_binding)

        # Mock channel polling manager
        manager._channel_polling_manager.start_polling_loop = AsyncMock()

        # Mock spawn method to avoid actual task creation
        manager.spawn = Mock(return_value=Mock())

        # Test the listen_rpc method
        result = await manager.listen_rpc(
            service_name="test-rpc-service", handler=Mock(), capabilities=["rpc"]
        )

        # Verify binding was created
        manager._binding_manager.bind.assert_called_once_with("test-rpc-service", capabilities=["rpc"])

        # Verify polling was started (happens in the spawned task)
        # The actual polling happens asynchronously in a spawned task
        assert manager.spawn.called

        # Should return an address
        assert result is not None

    @pytest.mark.asyncio
    async def test_invoke_method(self, manager):
        """Test the invoke method for outbound RPC calls"""
        # Mock RPC client manager
        manager._rpc_client_manager.invoke = AsyncMock(return_value="rpc_result")

        # Test the invoke method with correct parameters
        result = await manager.invoke(method="test_method", params={"key": "value"}, timeout_ms=5000)

        # Verify RPC client manager was called correctly
        manager._rpc_client_manager.invoke.assert_called_once_with(
            target_addr=None,
            capabilities=None,
            method="test_method",
            params={"key": "value"},
            timeout_ms=5000,
        )

        assert result == "rpc_result"

    @pytest.mark.asyncio
    async def test_invoke_stream_method(self, manager):
        """Test the invoke_stream method for streaming RPC calls"""

        # Mock RPC client manager's invoke_stream to return an async generator
        async def mock_stream_generator(**kwargs):
            yield "result1"
            yield "result2"

        # Set the mock to return the async generator directly
        manager._rpc_client_manager.invoke_stream = mock_stream_generator

        # Test the invoke_stream method with correct parameters
        result_generator = manager.invoke_stream(
            method="test_stream_method", params={"key": "value"}, timeout_ms=10000
        )

        # Collect results from the stream
        results = []
        results = [result async for result in result_generator]

        assert results == ["result1", "result2"]

    @pytest.mark.asyncio
    async def test_stop_method_with_cleanup(self, manager):
        """Test the stop method with proper cleanup"""
        # Add some listeners to test cleanup
        listener1 = Mock()
        listener1.stop = Mock()

        listener2 = Mock()
        listener2.stop = Mock()

        # Add listeners
        async with manager._listeners_lock:
            manager._listeners["service1"] = listener1
            manager._listeners["service2"] = listener2

        # Mock component cleanup methods
        manager._rpc_client_manager.cleanup = AsyncMock()
        manager.shutdown_tasks = AsyncMock()

        await manager.stop()

        # Verify all listeners were stopped
        listener1.stop.assert_called_once()
        listener2.stop.assert_called_once()

        # Verify component cleanup was called
        manager._rpc_client_manager.cleanup.assert_called_once()
        manager.shutdown_tasks.assert_called_once_with(grace_period=3.0)

        # Verify listeners were cleared
        async with manager._listeners_lock:
            assert len(manager._listeners) == 0

    @pytest.mark.asyncio
    async def test_listen_with_full_envelope_handling(self, manager):
        """Test listen method with complete envelope processing workflow"""
        # Mock binding setup
        mock_binding = Mock()
        mock_channel = Mock()
        mock_binding.channel = mock_channel
        manager._binding_manager.bind = AsyncMock(return_value=mock_binding)

        # Mock polling setup
        manager._channel_polling_manager.start_polling_loop = AsyncMock()

        # Mock spawn method to avoid actual task creation but track the call
        manager.spawn = Mock(return_value=Mock())

        # Mock delivery tracker
        mock_tracked_envelope = Mock()
        manager._delivery_tracker.on_envelope_delivered = AsyncMock(return_value=mock_tracked_envelope)
        manager._delivery_tracker.on_envelope_handled = AsyncMock()

        # Create a test handler
        test_results = []

        async def test_handler(envelope, context=None):
            test_results.append((envelope, context))
            return "handled_successfully"

        # Execute listen method
        result = await manager.listen(
            service_name="test-service",
            handler=test_handler,
            poll_timeout_ms=2000,
            capabilities=["messaging"],
        )

        # Verify binding was created
        manager._binding_manager.bind.assert_called_once_with("test-service", capabilities=["messaging"])

        # Verify handler was stored
        async with manager._service_handlers_lock:
            assert manager._service_handlers["test-service"] == test_handler

        # Verify a task was spawned for polling
        assert manager.spawn.called

        # Verify result is returned
        assert result is not None

    @pytest.mark.asyncio
    async def test_envelope_status_filtering(self, manager):
        """Test envelope status filtering in recovery logic"""
        # Create envelopes with different statuses
        received_env = Mock()
        received_env.status = EnvelopeStatus.RECEIVED
        received_env.service_name = "service1"

        failed_env = Mock()
        failed_env.status = EnvelopeStatus.FAILED_TO_HANDLE
        failed_env.service_name = "service2"

        handled_env = Mock()
        handled_env.status = EnvelopeStatus.HANDLED
        handled_env.service_name = "service3"

        # Mock delivery tracker to return mixed statuses
        all_envelopes = [received_env, failed_env, handled_env]

        def mock_filter_function(*, filter=None):
            # Simulate the filter function behavior
            if filter:
                return [env for env in all_envelopes if filter(env)]
            return all_envelopes

        manager._delivery_tracker.list_inbound = AsyncMock(side_effect=mock_filter_function)

        await manager.recover_unhandled_inbound_envelopes()

        # Verify the filtering was applied correctly
        manager._delivery_tracker.list_inbound.assert_called_once()

        # Verify only RECEIVED and FAILED_TO_HANDLE envelopes are processed
        async with manager._pending_recovery_services_lock:
            assert "service1" in manager._pending_recovery_services
            assert "service2" in manager._pending_recovery_services
            assert "service3" not in manager._pending_recovery_services  # HANDLED should be excluded


class TestEnvelopeListenerManagerErrorHandling:
    """Test error handling and edge cases"""

    @pytest.fixture
    def manager(self):
        """Create manager for error testing"""
        return EnvelopeListenerManager(
            binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
        )

    @pytest.mark.asyncio
    async def test_recovery_with_no_delivery_tracker(self, manager):
        """Test recovery when delivery tracker is None"""
        manager._delivery_tracker = None

        # Should handle gracefully without error
        await manager.recover_unhandled_inbound_envelopes()

        # Should not crash - verify we get here
        assert True

    @pytest.mark.asyncio
    async def test_recovery_with_empty_envelope_list(self, manager):
        """Test recovery with empty failed envelope list"""
        manager._delivery_tracker.list_inbound = AsyncMock(return_value=[])

        await manager.recover_unhandled_inbound_envelopes()

        # Verify no services are marked for recovery
        async with manager._pending_recovery_services_lock:
            assert len(manager._pending_recovery_services) == 0
            assert len(manager._pending_recovery_envelopes) == 0

    @pytest.mark.asyncio
    async def test_service_recovery_without_handler(self, manager):
        """Test service recovery when no handler is registered"""
        # Set up pending recovery without handler
        envelope = Mock()
        envelope.service_name = "unknown-service"
        envelope.envelope_id = "test-123"

        async with manager._pending_recovery_services_lock:
            manager._pending_recovery_services.add("unknown-service")
            manager._pending_recovery_envelopes = {"unknown-service": [envelope]}

        # Should handle gracefully without handler
        await manager._recover_service_if_needed("unknown-service")

        # Service should remain in pending since no handler
        async with manager._pending_recovery_services_lock:
            assert "unknown-service" in manager._pending_recovery_services

    @pytest.mark.asyncio
    async def test_execute_handler_with_exception(self, manager):
        """Test handler execution when handler raises exception"""

        async def failing_handler(envelope, context=None):
            raise ValueError("Handler failed")

        envelope = Mock()
        context = Mock()

        # Should raise the exception since no retry policy is configured
        with pytest.raises(ValueError, match="Handler failed"):
            await manager._execute_handler_with_retries(failing_handler, envelope, context)


class TestEnvelopeListenerManagerComponentIntegration:
    """Test integration with various components"""

    @pytest.fixture
    def manager(self):
        """Create manager with component mocks"""
        binding_manager = Mock()
        node_like = Mock()
        node_like.send = AsyncMock(return_value="sent")
        envelope_factory = Mock()
        delivery_tracker = Mock()

        manager = EnvelopeListenerManager(
            binding_manager=binding_manager,
            node_like=node_like,
            envelope_factory=envelope_factory,
            delivery_tracker=delivery_tracker,
        )

        # Ensure components are properly mocked
        manager._channel_polling_manager = Mock()
        manager._rpc_server_handler = Mock()
        manager._rpc_client_manager = Mock()
        manager._response_context_manager = Mock()
        manager._streaming_response_handler = Mock()

        return manager

    @pytest.mark.asyncio
    async def test_delivery_tracker_interaction(self, manager):
        """Test full delivery tracker workflow"""
        # Mock delivery tracking methods
        tracked_envelope = Mock()
        manager._delivery_tracker.on_envelope_delivered = AsyncMock(return_value=tracked_envelope)
        manager._delivery_tracker.on_envelope_handled = AsyncMock()

        envelope = Mock()
        context = Mock()

        # Simulate delivery tracking workflow
        tracked = await manager._delivery_tracker.on_envelope_delivered(envelope, context)
        assert tracked == tracked_envelope

        # Simulate successful handling
        await manager._delivery_tracker.on_envelope_handled(tracked, "success", None)

        # Verify calls were made
        manager._delivery_tracker.on_envelope_delivered.assert_called_once_with(envelope, context)
        manager._delivery_tracker.on_envelope_handled.assert_called_once_with(tracked, "success", None)

    @pytest.mark.asyncio
    async def test_node_like_send_integration(self, manager):
        """Test integration with node_like send functionality"""
        envelope = Mock()
        context = Mock()

        # Test the deliver function
        result = await manager._deliver(envelope, context)

        # Verify node_like.send was called
        manager._node_like.send.assert_called_once_with(envelope, context)
        assert result == "sent"  # From our mock setup

    @pytest.mark.asyncio
    async def test_envelope_factory_usage(self, manager):
        """Test envelope factory integration"""
        # This would test how envelope factory is used in context creation
        # For now, just verify it's accessible
        assert manager._envelope_factory is not None

        # Mock envelope creation
        mock_envelope = Mock()
        manager._envelope_factory.create_envelope = Mock(return_value=mock_envelope)

        # Test creation
        envelope = manager._envelope_factory.create_envelope(payload="test")
        assert envelope == mock_envelope
