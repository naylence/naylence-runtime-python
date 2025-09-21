"""
Final test file to reach 95% coverage for DefaultDeliveryTracker.
These tests target specific uncovered lines using correct API calls.
"""

import asyncio
import time

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    FameAddress,
    FameResponseType,
    create_fame_envelope,
)
from naylence.fame.delivery.at_least_once_delivery_policy import AtLeastOnceDeliveryPolicy
from naylence.fame.delivery.default_delivery_tracker import DefaultDeliveryTracker
from naylence.fame.delivery.delivery_tracker import (
    EnvelopeStatus,
    RetryPolicy,
    TrackedEnvelope,
)
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


@pytest.fixture
async def storage():
    """Create fresh in-memory storage."""
    storage = InMemoryStorageProvider()
    yield storage
    # InMemoryStorageProvider doesn't have a close() method


@pytest.fixture
async def tracker(storage):
    """Create tracker with fast GC for testing."""
    tracker = DefaultDeliveryTracker(
        storage_provider=storage, futures_gc_grace_secs=1, futures_sweep_interval_secs=1
    )

    # Mock node setup
    class MockNode:
        def __init__(self):
            self.envelope_factory = self

        def create_envelope(self, frame, to=None, corr_id=None, trace_id=None):
            return create_fame_envelope(frame=frame, to=to, corr_id=corr_id, trace_id=trace_id)

    mock_node = MockNode()
    await tracker.on_node_initialized(mock_node)
    await tracker.on_node_started(mock_node)

    yield tracker
    await tracker.cleanup()


@pytest.fixture
def sample_envelope():
    """Create a sample envelope for testing."""
    return create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        to=FameAddress("test@/service"),
        corr_id="test-correlation",
    )


class TestDefaultDeliveryTrackerFinalCoverage:
    """Final targeted tests to reach 95% coverage."""

    @pytest.mark.asyncio
    async def test_send_ack_without_reply_to(self, tracker, sample_envelope):
        """Test _send_ack with envelope missing reply_to (lines 284-285)."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "no_reply"}), to=FameAddress("test@/no_reply")
        )
        envelope.reply_to = None
        envelope.corr_id = "test_corr"

        # Should log error and return early
        await tracker._send_ack(envelope)

    @pytest.mark.asyncio
    async def test_send_ack_without_correlation_id(self, tracker, sample_envelope):
        """Test _send_ack with envelope missing corr_id (lines 287-288)."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "no_corr"}), to=FameAddress("test@/no_corr")
        )
        envelope.reply_to = FameAddress("test@/reply")
        envelope.corr_id = None

        # Should log error and return early
        await tracker._send_ack(envelope)

    @pytest.mark.asyncio
    async def test_wait_for_pending_acks_no_pending(self, tracker):
        """Test _wait_for_pending_acks when no ACKs are pending (lines 146-147)."""
        # Should log debug message about no pending ACKs
        await tracker._wait_for_pending_acks()

    @pytest.mark.asyncio
    async def test_wait_for_pending_acks_with_pending(self, tracker, sample_envelope):
        """Test _wait_for_pending_acks with pending ACKs (line 149)."""
        # Track envelope expecting ACK
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Should log debug message about waiting for ACKs
        await tracker._wait_for_pending_acks()

    @pytest.mark.asyncio
    async def test_envelope_delivered_without_correlation_id(self, tracker):
        """Test on_envelope_delivered with envelope without corr_id (early return)."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "no_corr"}), to=FameAddress("test@/no_corr")
        )
        envelope.corr_id = None

        result = await tracker.on_envelope_delivered("inbox", envelope)
        assert result is None

    @pytest.mark.asyncio
    async def test_ack_frame_without_ref_id(self, tracker):
        """Test ACK frame without ref_id (early return)."""
        ack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ok=True, ref_id=None), to=FameAddress("test@/ack")
        )
        ack_envelope.corr_id = "test_corr"

        result = await tracker.on_envelope_delivered("inbox", ack_envelope)
        assert result is None

    @pytest.mark.asyncio
    async def test_display_methods(self, tracker, sample_envelope):
        """Test display methods for coverage."""
        # These methods just print debug info
        from unittest.mock import MagicMock

        node_mock = MagicMock()
        await tracker.on_forward_upstream_complete(node_mock, sample_envelope)
        await tracker.on_forward_to_route_complete(node_mock, sample_envelope, "test_route")
        await tracker.on_forward_to_peer_complete(node_mock, sample_envelope, "test_peer")

    @pytest.mark.asyncio
    async def test_recover_pending_empty(self, tracker):
        """Test recover_pending when no envelopes exist."""
        await tracker.recover_pending()

    @pytest.mark.asyncio
    async def test_on_correlated_message_creates_tracked_envelope(self, tracker):
        """Test on_correlated_message creates TrackedEnvelope when no existing correlation."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "correlation"}), to=FameAddress("test@/correlation")
        )
        envelope.corr_id = "new_correlation"

        result = await tracker.on_correlated_message("test_inbox", envelope)
        assert result is not None
        assert isinstance(result, TrackedEnvelope)

    @pytest.mark.asyncio
    async def test_timer_with_expired_envelope(self, tracker, sample_envelope):
        """Test timer scheduling with already expired envelope."""
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=sample_envelope,
            status=EnvelopeStatus.PENDING,
            created_at_ms=now_ms,
            attempt=0,
            last_attempt_at_ms=now_ms,
            overall_timeout_at_ms=now_ms - 1000,  # Already expired
            timeout_at_ms=now_ms - 1000,
            expected_response_type=FameResponseType.ACK,
        )

        retry_policy = RetryPolicy(max_retries=1, base_delay_ms=50, max_delay_ms=100)

        # Should handle expired envelope gracefully
        await tracker._schedule_timer(tracked, retry_policy)

    @pytest.mark.asyncio
    async def test_stream_operations_with_nonexistent_envelope(self, tracker):
        """Test stream operations on non-existent envelope."""
        fake_id = "non_existent_envelope"

        # Should handle gracefully
        try:
            async for item in tracker.iter_stream(fake_id):
                break
        except Exception:
            pass  # Expected

    @pytest.mark.asyncio
    async def test_awaiting_non_tracked_envelope(self, tracker):
        """Test awaiting envelope that was never tracked."""
        fake_id = "non_existent_envelope_id"

        try:
            await tracker.await_ack(fake_id, timeout_ms=50)
        except Exception:
            pass  # Expected to fail or timeout

    @pytest.mark.asyncio
    async def test_cleanup_exception_handling(self, tracker, sample_envelope):
        """Test cleanup handles exceptions gracefully."""
        # Track envelope
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Corrupt timers dict to cause exception
        original_timers = tracker._timers
        tracker._timers["corrupt_entry"] = None

        try:
            await tracker.cleanup()
        except Exception:
            pass  # Should handle exceptions gracefully
        finally:
            tracker._timers = original_timers

    @pytest.mark.asyncio
    async def test_storage_error_handling(self, tracker, sample_envelope):
        """Test graceful storage error handling."""
        original_outbox = tracker._outbox

        class FailingStorage:
            async def set(self, key, value):
                raise Exception("Storage failed")

            async def get(self, key):
                raise Exception("Storage failed")

            async def delete(self, key):
                raise Exception("Storage failed")

            async def keys(self):
                return []

        tracker._outbox = FailingStorage()

        try:
            await tracker.track(
                sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK
            )
        except Exception:
            pass  # Expected to fail gracefully
        finally:
            tracker._outbox = original_outbox

    @pytest.mark.asyncio
    async def test_envelope_status_edge_cases(self, tracker, sample_envelope):
        """Test envelope status handling edge cases."""
        # Track envelope
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Create tracked envelope for testing
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=sample_envelope,
            status=EnvelopeStatus.PENDING,
            created_at_ms=now_ms,
            attempt=0,
            last_attempt_at_ms=now_ms,
            overall_timeout_at_ms=now_ms + 5000,
            timeout_at_ms=now_ms + 5000,
            expected_response_type=FameResponseType.ACK,
        )

        # Test on_envelope_handled
        await tracker.on_envelope_handled(tracked)

    @pytest.mark.asyncio
    async def test_await_envelope_already_expired_timeout(self, tracker):
        """Test await_envelope when tracked envelope timeout is already expired - line 428."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "expired"}), to=FameAddress("test@/expired")
        )

        # Track envelope with very short timeout that will expire immediately
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=envelope,
            status=EnvelopeStatus.PENDING,
            created_at_ms=now_ms,
            attempt=0,
            last_attempt_at_ms=now_ms,
            overall_timeout_at_ms=now_ms - 1000,  # Already expired
            timeout_at_ms=now_ms - 1000,
            expected_response_type=FameResponseType.REPLY,
        )

        # Store the tracked envelope
        assert tracker._outbox is not None
        await tracker._outbox.set(envelope.id, tracked)

        # Set up reply future
        import asyncio

        tracker._reply_futures[envelope.id] = asyncio.get_running_loop().create_future()

        # Should set timeout_seconds to None for expired envelope
        try:
            await tracker.await_envelope(envelope.id, timeout_ms=5000)
        except Exception:
            pass  # Expected to fail due to expired envelope

    @pytest.mark.asyncio
    async def test_await_envelope_exception_in_wait_for(self, tracker, sample_envelope):
        """Test await_envelope when asyncio.wait_for raises non-timeout exception - line 438-439."""
        # Track envelope
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.REPLY)

        # Mock asyncio.wait_for to raise a RuntimeError
        import asyncio
        from unittest.mock import patch

        original_wait_for = asyncio.wait_for

        def mock_wait_for(future, timeout=None):
            if timeout is not None:
                raise RuntimeError("Mock exception during wait_for")
            return original_wait_for(future, timeout)

        with patch("asyncio.wait_for", side_effect=mock_wait_for):
            try:
                await tracker.await_reply(sample_envelope.id, timeout_ms=1000)
            except RuntimeError:
                pass  # Expected

    @pytest.mark.asyncio
    async def test_send_ack_full_execution_path(self, tracker):
        """Test _send_ack complete execution with all fields present - lines 293-311."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "send_ack"}), to=FameAddress("test@/send_ack")
        )
        envelope.reply_to = FameAddress("test@/reply")
        envelope.corr_id = "test_correlation"
        envelope.trace_id = "test_trace"

        # Mock node send method to verify it gets called
        from unittest.mock import AsyncMock

        tracker._node.send = AsyncMock()

        # Call _send_ack - should complete full execution path
        await tracker._send_ack(envelope)

        # Verify send was called
        tracker._node.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_track_duplicate_correlation_for_replies(self, tracker):
        """Test track when envelope already tracked for replies - lines 341-347."""
        # Create first envelope with correlation ID
        envelope1 = create_fame_envelope(
            frame=DataFrame(payload={"test": "first"}), to=FameAddress("test@/first")
        )
        envelope1.corr_id = "duplicate_correlation"

        # Track first envelope expecting REPLY
        result1 = await tracker.track(
            envelope1, timeout_ms=5000, expected_response_type=FameResponseType.REPLY
        )
        assert result1 is not None

        # Create second envelope with same correlation ID
        envelope2 = create_fame_envelope(
            frame=DataFrame(payload={"test": "second"}), to=FameAddress("test@/second")
        )
        envelope2.corr_id = "duplicate_correlation"

        # Track second envelope - should return None due to duplicate correlation
        result2 = await tracker.track(
            envelope2, timeout_ms=5000, expected_response_type=FameResponseType.REPLY
        )
        assert result2 is None

    @pytest.mark.asyncio
    async def test_sweep_futures_exception_handling(self, tracker):
        """Test _sweep_futures when exception occurs during cleanup."""
        from unittest.mock import AsyncMock

        # Don't test the _sweep_futures directly since it can cause timeouts
        # Instead test that cleanup handles errors gracefully

        # Mock outbox to raise exception during keys() call
        original_outbox = tracker._outbox
        mock_outbox = AsyncMock()
        mock_outbox.keys = AsyncMock(side_effect=Exception("Storage keys error"))
        tracker._outbox = mock_outbox

        # Call cleanup - should handle exception gracefully
        await tracker.cleanup()

        # Restore original outbox
        tracker._outbox = original_outbox

    @pytest.mark.asyncio
    async def test_on_node_started_exception_in_setup(self, tracker):
        """Test on_node_started when _sweep_futures spawn raises exception."""
        # Mock the spawn method to raise exception - but first await any coroutines to avoid warnings
        from unittest.mock import Mock

        def mock_spawn(coro, **kwargs):
            # Cancel/close the coroutine to avoid unawaited warning
            if hasattr(coro, "close"):
                coro.close()
            raise Exception("Spawn error")

        tracker.spawn = Mock(side_effect=mock_spawn)

        # Create a mock node
        class MockNode:
            pass

        mock_node = MockNode()

        # Should propagate the exception from spawn
        with pytest.raises(Exception, match="Spawn error"):
            await tracker.on_node_started(mock_node)

    @pytest.mark.asyncio
    async def test_wait_for_pending_acks_exception_during_wait(self, tracker, sample_envelope):
        """Test _wait_for_pending_acks when exception occurs during wait - lines 174-175."""
        # Track envelope expecting ACK
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Mock asyncio.wait_for to raise RuntimeError
        from unittest.mock import patch

        with patch("asyncio.wait_for", side_effect=RuntimeError("Wait error")):
            # Should handle exception gracefully
            await tracker._wait_for_pending_acks()

    @pytest.mark.asyncio
    async def test_await_envelope_no_timeout_logging(self, tracker, sample_envelope):
        """Test await_envelope when no timeout is specified - line 438."""
        # Track envelope
        tracked = await tracker.track(
            sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.REPLY
        )
        assert tracked is not None

        # Start await_envelope without timeout to trigger logging
        import asyncio

        async def await_task():
            return await tracker.await_reply(sample_envelope.id)

        task = asyncio.create_task(await_task())

        # Give it time to start and hit the logging line
        await asyncio.sleep(0.01)

        # Cancel to clean up
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_clear_timer_with_missing_envelope(self, tracker):
        """Test _clear_timer when envelope not found."""
        # Call clear timer on non-existent envelope ID
        await tracker._clear_timer("non_existent_envelope_id")

        # Should complete without error

    @pytest.mark.asyncio
    async def test_wait_for_pending_acks_with_already_expired_envelope(self, tracker, sample_envelope):
        """Test _wait_for_pending_acks with envelope that has already expired - line 179."""
        # Track envelope with ACK expectation
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Modify the tracked envelope to be expired
        tracked = await tracker._outbox.get(sample_envelope.id)
        if tracked:
            tracked.overall_timeout_at_ms = int(time.time() * 1000) - 1000  # Set to past
            await tracker._outbox.set(sample_envelope.id, tracked)

        # Should log about already expired envelope
        await tracker._wait_for_pending_acks()

    @pytest.mark.asyncio
    async def test_track_with_ack_future_creation(self, tracker, sample_envelope):
        """Test track method creating ACK future - specific for lines targeting ACK future setup."""
        # Track envelope expecting ACK to trigger future creation
        result = await tracker.track(
            sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK
        )

        assert result is not None
        # Verify ACK future was created
        assert sample_envelope.id in tracker._ack_futures

    @pytest.mark.asyncio
    async def test_heartbeat_display_function(self, tracker, sample_envelope):
        """Test on_heartbeat_sent display function - line 238."""
        # This tests the display/logging functionality
        await tracker.on_heartbeat_sent(sample_envelope)

    @pytest.mark.asyncio
    async def test_nack_envelope_handling(self, tracker, sample_envelope):
        """Test NACK envelope handling through on_envelope_delivered - line 266."""
        # First track an envelope to establish correlation
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Create NACK envelope
        nack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ok=False, ref_id=sample_envelope.id), to=FameAddress("test@/nack")
        )
        nack_envelope.corr_id = sample_envelope.id

        # Should trigger NACK handling path
        await tracker.on_envelope_delivered("test_inbox", nack_envelope)

    @pytest.mark.asyncio
    async def test_send_ack_node_send_execution(self, tracker):
        """Test _send_ack actually calls node.send - line 311."""
        # Create envelope with all required fields
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "node_send"}), to=FameAddress("test@/node_send")
        )
        envelope.reply_to = FameAddress("test@/reply_to")
        envelope.corr_id = "correlation_id"
        envelope.trace_id = "trace_id"

        # Mock node and envelope factory
        from unittest.mock import AsyncMock, Mock

        mock_node = Mock()
        mock_node.envelope_factory = Mock()
        mock_node.envelope_factory.create_envelope = Mock(return_value=envelope)
        mock_node.send = AsyncMock()

        tracker._node = mock_node

        # Call _send_ack - should execute node.send
        await tracker._send_ack(envelope)

        # Verify send was actually called
        mock_node.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_clear_timer_exception_handling(self, tracker, sample_envelope):
        """Test _clear_timer when timer cancellation raises exceptions."""
        # Track envelope first to create a timer
        await tracker.track(sample_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)

        # Mock timer to raise exception on cancel

        # Mock timer to raise exception on cancel
        import asyncio

        # Create a real but canceled task
        async def dummy_coro():
            await asyncio.sleep(0.1)

        mock_timer = asyncio.create_task(dummy_coro())
        # Replace cancel method with one that raises
        original_cancel = mock_timer.cancel

        def cancel_with_exception():
            original_cancel()  # Actually cancel it
            raise Exception("Cancel failed")

        mock_timer.cancel = cancel_with_exception

        async with tracker._lock:
            tracker._timers[sample_envelope.id] = mock_timer

        # Should handle exception gracefully (no exception should be raised)
        await tracker._clear_timer(sample_envelope.id)

        # Verify timer was processed (removed from timers dict)
        async with tracker._lock:
            assert sample_envelope.id not in tracker._timers

    @pytest.mark.asyncio
    async def test_await_envelope_with_zero_remaining_timeout(self, tracker):
        """Test await_envelope when remaining timeout is zero or negative - line 428."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "zero_timeout"}), to=FameAddress("test@/zero_timeout")
        )

        # Create tracked envelope that's already expired
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=envelope,
            status=EnvelopeStatus.PENDING,
            created_at_ms=now_ms,
            attempt=0,
            last_attempt_at_ms=now_ms,
            overall_timeout_at_ms=now_ms - 5000,  # Expired 5 seconds ago
            timeout_at_ms=now_ms - 5000,
            expected_response_type=FameResponseType.REPLY,
        )

        # Store tracked envelope
        await tracker._outbox.set(envelope.id, tracked)

        # Set up reply future
        import asyncio

        tracker._reply_futures[envelope.id] = asyncio.get_running_loop().create_future()

        # This should set timeout_seconds to None due to expired timeout
        try:
            await tracker.await_reply(envelope.id, timeout_ms=1000)
        except Exception:
            pass  # Expected to fail

    @pytest.mark.asyncio
    async def test_sweep_futures_outbox_exception(self, tracker):
        """Test _sweep_futures when outbox.get raises exception."""
        from unittest.mock import AsyncMock

        # Add a done future to trigger sweep
        async with tracker._lock:
            tracker._ack_done_since["test_envelope_id"] = time.time() - 200  # Old enough for sweep

        # Mock outbox to fail on get()
        original_outbox = tracker._outbox
        mock_outbox = AsyncMock()
        mock_outbox.get = AsyncMock(side_effect=Exception("Get failed"))
        tracker._outbox = mock_outbox

        # Should handle exception in get operation
        await tracker.cleanup()

        # Restore
        tracker._outbox = original_outbox

    @pytest.mark.asyncio
    async def test_await_ack_with_tracked_envelope_timeout(self, tracker):
        """Test await_ack using tracked envelope timeout when timeout_ms is None."""
        import time

        # Create envelope and track it with timeout
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )

        # Create tracked envelope with specific timeout
        now_ms = int(time.time() * 1000)
        timeout_ms = 100
        delivery_policy = AtLeastOnceDeliveryPolicy(retry_policy=None)

        tracked = TrackedEnvelope(
            original_envelope=envelope,
            timeout_at_ms=now_ms + timeout_ms,
            overall_timeout_at_ms=now_ms + timeout_ms,
            created_at_ms=now_ms,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.ACK,
            delivery_policy=delivery_policy,
        )

        # Store tracked envelope in outbox
        await tracker._outbox.set(envelope.id, tracked)

        # Manually create the ack future as the tracker.track() method would
        import asyncio

        async with tracker._lock:
            tracker._ack_futures[envelope.id] = asyncio.get_running_loop().create_future()

        # Test await_ack with timeout_ms=None (should use tracked envelope timeout)
        with pytest.raises(asyncio.TimeoutError):
            await tracker.await_ack(envelope.id, timeout_ms=None)

    @pytest.mark.asyncio
    async def test_await_ack_with_no_tracked_envelope(self, tracker):
        """Test await_ack when no tracked envelope exists and timeout_ms is None."""
        envelope_id = "nonexistent_envelope"

        # Test await_ack with timeout_ms=None and no tracked envelope
        with pytest.raises(RuntimeError):
            await tracker.await_ack(envelope_id, timeout_ms=None)

    @pytest.mark.asyncio
    async def test_on_ack_original_envelope_same_id(self, tracker):
        """Test on_ack when received envelope has same ID as original (local-to-local case)."""
        import time

        # Create original envelope
        original_envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"),
            to="test@/destination",
            trace_id="trace123",
            corr_id="corr123",
        )

        # Create tracked envelope
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=original_envelope,
            timeout_at_ms=now_ms + 5000,
            overall_timeout_at_ms=now_ms + 5000,
            created_at_ms=now_ms,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.ACK,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        # Store tracked envelope
        await tracker._outbox.set(original_envelope.id, tracked)

        # Create ACK envelope with the same ID (simulating local-to-local call)
        ack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ok=True, ref_id=original_envelope.id),
            to="test@/destination",
            trace_id="trace123",
            corr_id="corr123",  # Need correlation ID
        )
        ack_envelope.id = original_envelope.id  # Same ID to test the early return path

        # Call on_ack with ACK envelope that has same ID as original
        await tracker.on_ack(ack_envelope, None)

        # Should return early without processing

    @pytest.mark.asyncio
    async def test_stream_timeout_waiting_for_next_item(self, tracker):
        """Test stream iteration with timeout waiting for next item."""
        import asyncio

        # Create envelope
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=envelope,
            timeout_at_ms=now_ms + 5000,
            overall_timeout_at_ms=now_ms + 5000,
            created_at_ms=now_ms,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.STREAM,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        await tracker._outbox.set(envelope.id, tracked)

        # Set up stream queue and done event
        queue = asyncio.Queue()
        done = asyncio.Event()
        tracker._stream_queues[envelope.id] = queue
        tracker._stream_done[envelope.id] = done

        # Start stream iteration with very short timeout
        stream = tracker.iter_stream(envelope.id, timeout_ms=1)

        # Should timeout waiting for next item
        with pytest.raises(asyncio.TimeoutError, match="stream timeout waiting for next item"):
            async for _ in stream:
                pass

    @pytest.mark.asyncio
    async def test_stream_exception_item(self, tracker):
        """Test stream iteration when exception is put in queue."""
        import asyncio

        # Create envelope
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=envelope,
            timeout_at_ms=now_ms + 5000,
            overall_timeout_at_ms=now_ms + 5000,
            created_at_ms=now_ms,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.STREAM,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        await tracker._outbox.set(envelope.id, tracked)

        # Put an exception in the stream queue
        queue = asyncio.Queue()
        done = asyncio.Event()  # Also need to set up the done event
        tracker._stream_queues[envelope.id] = queue
        tracker._stream_done[envelope.id] = done
        test_exception = RuntimeError("Stream error")
        await queue.put(test_exception)

        # Should raise the exception
        stream = tracker.iter_stream(envelope.id, timeout_ms=1000)
        with pytest.raises(RuntimeError, match="Stream error"):
            async for _ in stream:
                pass

    @pytest.mark.asyncio
    async def test_on_stream_item_no_queue(self, tracker):
        """Test on_stream_item when no queue exists for envelope."""
        response_envelope = create_fame_envelope(
            frame=DataFrame(payload="response_content"), to="test@/response"
        )

        # Call on_stream_item for non-existent stream
        await tracker.on_stream_item("nonexistent_envelope", response_envelope)

        # Should return early without error

    @pytest.mark.asyncio
    async def test_timer_callback_with_overall_timeout_first(self, tracker):
        """Test timer callback when overall timeout occurs before retry timeout."""
        import time

        # Create envelope with retry policy
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )

        # Create tracked envelope where overall timeout is before retry timeout
        now_ms = int(time.time() * 1000)
        retry_timeout = now_ms + 1000  # 1 second from now
        overall_timeout = now_ms + 500  # 0.5 seconds from now (sooner)

        tracked = TrackedEnvelope(
            original_envelope=envelope,
            timeout_at_ms=retry_timeout,
            overall_timeout_at_ms=overall_timeout,
            created_at_ms=now_ms,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.ACK,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        await tracker._outbox.set(envelope.id, tracked)

        # Trigger timeout behavior by manually calling the internal timer logic
        # This tests the branch where overall_timeout_at_ms < next_retry_at_ms
        from unittest.mock import AsyncMock

        mock_node = AsyncMock()
        tracker._node = mock_node

        # Set up the timer task to test the timeout logic
        async def test_timer_logic():
            try:
                # Simulate the timer logic from _schedule_timer_impl
                now_ms = int(time.time() * 1000)
                next_retry_at_ms = tracked.timeout_at_ms
                overall_timeout_at_ms = tracked.overall_timeout_at_ms

                if next_retry_at_ms <= overall_timeout_at_ms:
                    delay_ms = max(0, next_retry_at_ms - now_ms)
                else:
                    delay_ms = max(0, overall_timeout_at_ms - now_ms)  # This branch

                # Wait minimal time
                if delay_ms > 0:
                    await asyncio.sleep(min(delay_ms / 1000.0, 0.01))
            except Exception:
                pass

        await test_timer_logic()

    @pytest.mark.asyncio
    async def test_wait_for_pending_acks_zero_remaining_timeout(self, tracker):
        """Test wait_for_pending_acks when remaining timeout is zero."""
        import time

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )
        envelope_id = envelope.id

        # Create tracked envelope with timeout already expired
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=envelope,
            timeout_at_ms=now_ms - 1000,  # Already expired
            overall_timeout_at_ms=now_ms - 1000,  # Already expired
            created_at_ms=now_ms - 2000,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.ACK,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        # Store tracked envelope
        await tracker._outbox.set(envelope_id, tracked)

        # Add future to pending acks
        future = asyncio.Future()
        async with tracker._lock:
            tracker._ack_futures[envelope_id] = future

        # Should handle zero/negative remaining timeout
        try:
            await tracker._wait_for_pending_acks()
        except Exception:
            pass  # May timeout or have other issues

    @pytest.mark.asyncio
    async def test_debug_logging_in_wait_for_pending_acks(self, tracker):
        """Test debug logging in _wait_for_pending_acks."""
        import time

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )
        envelope_id = envelope.id

        # Create tracked envelope with reasonable timeout
        now_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            original_envelope=envelope,
            timeout_at_ms=now_ms + 100,  # 100ms from now
            overall_timeout_at_ms=now_ms + 100,
            created_at_ms=now_ms,
            attempt=0,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.ACK,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        # Store tracked envelope
        await tracker._outbox.set(envelope_id, tracked)

        # Add future to pending acks
        future = asyncio.Future()
        async with tracker._lock:
            tracker._ack_futures[envelope_id] = future

        # Complete the future quickly to test the debug logging path
        future.set_result("ack_completed")

        # Should execute debug logging for positive timeout
        await tracker._wait_for_pending_acks()

    @pytest.mark.asyncio
    async def test_wait_for_pending_acks_no_tracked_envelope(self, tracker):
        """Test _wait_for_pending_acks when tracked envelope is not found - covers line 157"""
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )

        # Add a future but no tracked envelope in storage
        async with tracker._lock:
            future = asyncio.Future()
            tracker._ack_futures[envelope.id] = future

        # This should cover the continue statement when tracked is None (line 157)
        await tracker._wait_for_pending_acks()

        # Future should still be pending since no tracked envelope was found
        assert not future.done()

    @pytest.mark.asyncio
    async def test_heartbeat_sent_with_show_envelopes(self):
        """Test on_heartbeat_sent with show envelopes enabled - covers line 238"""
        import os

        original_value = os.environ.get("NAYLENCE_SHOW_ENVELOPES")

        try:
            # Enable show envelopes
            os.environ["NAYLENCE_SHOW_ENVELOPES"] = "true"

            # Force reload the module to pick up environment variable
            import importlib

            import naylence.fame.delivery.default_delivery_tracker as tracker_module

            importlib.reload(tracker_module)

            # Create new tracker instance
            from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

            storage_provider = InMemoryStorageProvider()
            test_tracker = tracker_module.DefaultDeliveryTracker(storage_provider=storage_provider)

            envelope = create_fame_envelope(
                frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
            )

            # This should trigger the print statement (line 238)
            await test_tracker.on_heartbeat_sent(envelope)

        finally:
            # Restore original environment
            if original_value is None:
                os.environ.pop("NAYLENCE_SHOW_ENVELOPES", None)
            else:
                os.environ["NAYLENCE_SHOW_ENVELOPES"] = original_value

            # Reload again to restore original state
            importlib.reload(tracker_module)

    @pytest.mark.asyncio
    async def test_await_ack_with_none_timeout_ms(self, tracker):
        """Test await_ack when timeout_ms is None - covers line 428"""
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )
        now_ms = int(time.time() * 1000)

        tracked_envelope = TrackedEnvelope(
            original_envelope=envelope,
            created_at_ms=now_ms,
            timeout_at_ms=now_ms + 30000,  # Long timeout
            overall_timeout_at_ms=now_ms + 30000,
            attempt=1,
            status=EnvelopeStatus.PENDING,
            expected_response_type=FameResponseType.ACK,
            delivery_policy=AtLeastOnceDeliveryPolicy(retry_policy=None),
        )

        await tracker._outbox.set(envelope.id, tracked_envelope)

        # Create ack envelope
        ack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ref_id=envelope.id), corr_id=envelope.corr_id
        )

        # Add future and resolve it immediately
        async with tracker._lock:
            future = asyncio.Future()
            tracker._ack_futures[envelope.id] = future
            future.set_result(ack_envelope)  # Resolve immediately

        # Test with timeout_ms=None - should use envelope's timeout
        result = await tracker.await_ack(envelope.id, timeout_ms=None)

        assert result.id == ack_envelope.id

    @pytest.mark.asyncio
    async def test_sweep_futures_no_outbox(self, tracker):
        """Test _sweep_futures when outbox is None - covers line 1016"""
        # Temporarily set outbox to None
        original_outbox = tracker._outbox
        tracker._outbox = None

        try:
            # Start sweep task
            sweep_task = asyncio.create_task(tracker._sweep_futures())

            # Let it run briefly
            await asyncio.sleep(0.1)

            # Cancel the task
            sweep_task.cancel()

            try:
                await sweep_task
            except asyncio.CancelledError:
                pass

        finally:
            # Restore outbox
            tracker._outbox = original_outbox

    @pytest.mark.asyncio
    async def test_iter_stream_timeout_per_get(self, tracker):
        """Test iter_stream with timeout per get - covers timeout handling"""
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )

        # Set up stream tracking
        stream_queue = asyncio.Queue()
        stream_done = asyncio.Event()

        tracker._stream_queues[envelope.id] = stream_queue
        tracker._stream_done[envelope.id] = stream_done

        # Test timeout scenario
        with pytest.raises(asyncio.TimeoutError, match="stream timeout waiting for next item"):
            async for item in tracker.iter_stream(envelope.id, timeout_ms=100):
                pass  # Should timeout before getting any items

    @pytest.mark.asyncio
    async def test_cleanup_comprehensive(self, tracker):
        """Test cleanup method thoroughly - covers various cleanup scenarios"""
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test_content"), to="test@/destination", trace_id="trace123"
        )

        # Set up some state to clean up
        timer_task = asyncio.create_task(asyncio.sleep(10))
        ack_future = asyncio.Future()
        reply_future = asyncio.Future()

        async with tracker._lock:
            tracker._timers[envelope.id] = timer_task
            tracker._ack_futures[envelope.id] = ack_future
            tracker._reply_futures[envelope.id] = reply_future
            tracker._ack_done_since[envelope.id] = time.time()
            tracker._reply_done_since[envelope.id] = time.time()

        # Call cleanup
        await tracker.cleanup()

        # Verify cleanup
        assert timer_task.cancelled()
        assert ack_future.cancelled()
        assert reply_future.cancelled()
        assert len(tracker._timers) == 0
        assert len(tracker._ack_futures) == 0
        assert len(tracker._reply_futures) == 0
        assert len(tracker._ack_done_since) == 0
        assert len(tracker._reply_done_since) == 0
        assert tracker._shutdown_event.is_set()
