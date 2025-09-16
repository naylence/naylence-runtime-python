"""
Ultra-focused test to hit the exact missing lines for 95% coverage.
This test is designed based on the exact coverage gaps identified.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.delivery.delivery_tracker import EnvelopeStatus
from naylence.fame.node.envelope_listener_manager import EnvelopeListenerManager


@pytest.mark.asyncio
async def test_recovery_envelope_grouping_workflow():
    """Test the exact envelope grouping and recovery workflow - targeting lines 155-165"""
    # Create manager
    manager = EnvelopeListenerManager(
        binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
    )

    # Create mock failed envelopes with different services
    env1 = Mock()
    env1.service_name = "service-a"
    env1.status = EnvelopeStatus.RECEIVED

    env2 = Mock()
    env2.service_name = "service-b"
    env2.status = EnvelopeStatus.FAILED_TO_HANDLE

    env3 = Mock()
    env3.service_name = None  # Test the "unknown" case
    env3.status = EnvelopeStatus.RECEIVED

    failed_envelopes = [env1, env2, env3]

    # Mock the delivery tracker to return our test envelopes
    # This simulates the filter function behavior
    def mock_list_inbound(filter):
        return [env for env in failed_envelopes if filter(env)]

    manager._delivery_tracker.list_inbound = AsyncMock(side_effect=mock_list_inbound)

    # Execute the recovery - this should hit lines 155-165 for grouping
    await manager.recover_unhandled_inbound_envelopes()

    # Verify the grouping worked (lines 155-165)
    async with manager._pending_recovery_services_lock:
        assert "service-a" in manager._pending_recovery_services
        assert "service-b" in manager._pending_recovery_services
        assert "unknown" in manager._pending_recovery_services  # env3 with None service_name

        assert "service-a" in manager._pending_recovery_envelopes
        assert "service-b" in manager._pending_recovery_envelopes
        assert "unknown" in manager._pending_recovery_envelopes


@pytest.mark.asyncio
async def test_service_recovery_with_actual_envelope_processing():
    """Test service recovery with actual envelope processing - targeting lines 277-290"""
    manager = EnvelopeListenerManager(
        binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
    )

    # Register a handler
    handled_envelopes = []

    async def test_handler(envelope, context=None):
        handled_envelopes.append(envelope)
        return "processed"

    async with manager._service_handlers_lock:
        manager._service_handlers["target-service"] = test_handler

    # Create envelope for recovery
    envelope = Mock()
    envelope.envelope_id = "test-env-123"
    envelope.original_envelope = Mock()
    envelope.attempt = 1
    envelope.status = "failed"

    # Set up pending recovery
    async with manager._pending_recovery_services_lock:
        manager._pending_recovery_services.add("target-service")
        manager._pending_recovery_envelopes = {"target-service": [envelope]}

    # Mock _execute_handler_with_retries to succeed
    with patch.object(manager, "_execute_handler_with_retries") as mock_execute:
        mock_execute.return_value = "success"

        # Execute recovery - should hit lines 277-290
        await manager._recover_service_if_needed("target-service")

        # Verify handler was called
        mock_execute.assert_called_once()

        # Verify cleanup happened (lines in the method)
        async with manager._pending_recovery_services_lock:
            assert "target-service" not in manager._pending_recovery_services


@pytest.mark.asyncio
async def test_listen_method_full_binding_workflow():
    """Test listen method with full binding and polling setup - targeting method lines"""
    manager = EnvelopeListenerManager(
        binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
    )

    # Mock binding manager
    mock_binding = Mock()
    mock_channel = Mock()
    mock_binding.channel = mock_channel
    manager._binding_manager.bind = AsyncMock(return_value=mock_binding)

    # Mock channel polling manager
    mock_task = Mock()
    mock_task.get_name.return_value = "listen-test-task"
    manager._channel_polling_manager = Mock()
    manager._channel_polling_manager.start_polling_loop = Mock(return_value=mock_task)

    # Create test handler
    async def listen_handler(envelope, context=None):
        return "listen_result"

    # Execute listen method
    result = await manager.listen(
        service_name="listen-test",
        handler=listen_handler,
        poll_timeout_ms=1000,
        capabilities=["test-capability"],
    )

    # Verify binding was created
    manager._binding_manager.bind.assert_called_once_with("listen-test", capabilities=["test-capability"])

    # Verify handler was stored
    async with manager._service_handlers_lock:
        assert manager._service_handlers["listen-test"] == listen_handler

    # Verify listener was stored
    async with manager._listeners_lock:
        assert "listen-test" in manager._listeners
        # Note: start_polling_loop is called asynchronously inside spawned task,
        # so we don't assert on it being called synchronously

    # Should return FameAddress
    assert result is not None


@pytest.mark.asyncio
async def test_execute_handler_with_delivery_tracker_workflows():
    """Test _execute_handler_with_retries with all delivery tracker paths"""
    manager = EnvelopeListenerManager(
        binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
    )

    # Test success path with delivery tracking
    async def success_handler(envelope, context=None):
        return "handler_success"

    envelope = Mock()
    context = Mock()
    tracked_envelope = Mock()
    tracked_envelope.attempt = 0  # Set as integer, not Mock

    # Mock delivery tracker success methods
    manager._delivery_tracker.on_envelope_handled = AsyncMock()

    # Create a proper RetryPolicy object
    from naylence.fame.delivery.retry_policy import RetryPolicy

    retry_policy = RetryPolicy(max_retries=3, base_delay_ms=100)

    # Execute success case
    result = await manager._execute_handler_with_retries(
        success_handler, envelope, context, retry_policy, tracked_envelope
    )

    assert result == "handler_success"
    manager._delivery_tracker.on_envelope_handled.assert_called_once_with(tracked_envelope, context=context)

    # Reset mocks
    manager._delivery_tracker.reset_mock()

    # Test failure path with delivery tracking
    async def failure_handler(envelope, context=None):
        raise Exception("Handler failure")

    tracked_envelope_fail = Mock()
    tracked_envelope_fail.attempt = 1

    # Mock delivery tracker failure methods
    manager._delivery_tracker.on_envelope_handle_failed = AsyncMock()

    # Execute failure case - expect exception to be raised after retries exhausted
    try:
        result_fail = await manager._execute_handler_with_retries(
            failure_handler, envelope, context, retry_policy, tracked_envelope_fail, "fail-service"
        )
        # If no exception raised, ensure result is None
        assert result_fail is None
    except Exception:
        # Exception is expected when retries are exhausted
        pass  # Verify failure tracking - called multiple times during retries
    assert manager._delivery_tracker.on_envelope_handle_failed.call_count >= 1

    # Verify attempt was incremented to final value (starting from 1 + 3 retries = 4)
    assert tracked_envelope_fail.attempt == 4


@pytest.mark.asyncio
async def test_start_method_with_recovery():
    """Test start method that triggers recovery"""
    manager = EnvelopeListenerManager(
        binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
    )

    # Mock the recovery method
    manager.recover_unhandled_inbound_envelopes = AsyncMock()

    # Execute start
    await manager.start()

    # Verify recovery was triggered
    manager.recover_unhandled_inbound_envelopes.assert_called_once()


@pytest.mark.asyncio
async def test_stop_method_with_listener_cleanup():
    """Test stop method with listener cleanup"""
    manager = EnvelopeListenerManager(
        binding_manager=Mock(), node_like=Mock(), envelope_factory=Mock(), delivery_tracker=Mock()
    )

    # Add mock listeners
    listener1 = Mock()
    listener1.task = Mock()
    listener1.task.cancel = Mock()
    listener1.stop = Mock(side_effect=lambda: listener1.task.cancel())

    listener2 = Mock()
    listener2.task = Mock()
    listener2.task.cancel = Mock()
    listener2.stop = Mock(side_effect=lambda: listener2.task.cancel())

    async with manager._listeners_lock:
        manager._listeners["service1"] = listener1
        manager._listeners["service2"] = listener2

    # Mock only the components that are actually called in stop()
    manager._rpc_client_manager = Mock()
    manager._rpc_client_manager.cleanup = AsyncMock()
    manager.shutdown_tasks = AsyncMock()

    # Execute stop
    await manager.stop()

    # Verify listeners were cancelled and cleared
    listener1.stop.assert_called_once()
    listener2.stop.assert_called_once()
    listener1.task.cancel.assert_called_once()
    listener2.task.cancel.assert_called_once()

    async with manager._listeners_lock:
        assert len(manager._listeners) == 0

    # Verify component stops - only these two methods are called in stop()
    manager._rpc_client_manager.cleanup.assert_called_once()
    manager.shutdown_tasks.assert_called_once_with(grace_period=3.0)
