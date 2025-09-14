import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    FameAddress,
    FameResponseType,
    create_fame_envelope,
)
from naylence.fame.delivery.default_delivery_tracker import DefaultDeliveryTracker
from naylence.fame.delivery.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerConfig,
    DefaultDeliveryTrackerFactory,
)
from naylence.fame.delivery.delivery_tracker import (
    EnvelopeStatus,
    RetryPolicy,
    TrackedEnvelope,
)
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


@pytest.fixture
def sample_envelope():
    """Create a sample envelope for testing."""
    return create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        to=FameAddress("test@/service"),
        corr_id="test-correlation-123",
    )


@pytest.fixture
async def in_memory_storage():
    """Create an in-memory storage provider."""
    return InMemoryStorageProvider()


@pytest.fixture
async def storage_tracker(in_memory_storage):
    """Create a storage-backed tracker for testing."""

    factory = DefaultDeliveryTrackerFactory()
    tracker = await factory.create(storage_provider=in_memory_storage)

    # Manually initialize the tracker like a node would
    mock_node = MagicMock()
    await tracker.on_node_initialized(mock_node)
    await tracker.on_node_started(mock_node)

    yield tracker
    await tracker.cleanup()


class TestRetryPolicy:
    """Test retry policy calculations."""

    def test_retry_delay_calculation(self):
        """Test retry delay calculations with backoff."""
        policy = RetryPolicy(
            max_retries=3,
            base_delay_ms=100,
            max_delay_ms=1000,
            backoff_factor=2.0,
            jitter_ms=10,
        )

        # First retry
        delay1 = policy.next_delay_ms(1)
        assert 190 <= delay1 <= 210  # 100 * 2^1 ± jitter

        # Second retry
        delay2 = policy.next_delay_ms(2)
        assert 390 <= delay2 <= 410  # 100 * 2^2 ± jitter

        # Should cap at max_delay_ms
        delay_large = policy.next_delay_ms(10)
        assert delay_large <= 1010  # max + jitter


class TestDefaultDeliveryTracker:
    """Test the default envelope tracker implementation."""

    @pytest.fixture
    async def kv_store(self, in_memory_storage):
        """Create a KeyValue store for testing."""
        return await in_memory_storage.get_kv_store(TrackedEnvelope, namespace="test_envelope")

    @pytest.fixture
    async def default_tracker(self, in_memory_storage):
        """Create a default tracker for testing."""
        factory = DefaultDeliveryTrackerFactory()
        tracker = await factory.create(storage_provider=in_memory_storage)

        # Manually initialize the tracker like a node would
        mock_node = MagicMock()
        await tracker.on_node_initialized(mock_node)
        await tracker.on_node_started(mock_node)

        yield tracker
        await tracker.cleanup()

    @pytest.mark.asyncio
    async def test_tracker_creation(self, kv_store):
        """Test creating a default tracker."""
        tracker = DefaultDeliveryTracker(kv_store)
        assert tracker is not None
        await tracker.cleanup()

    @pytest.mark.asyncio
    async def test_register_and_retrieve_envelope(self, default_tracker, sample_envelope):
        """Test registering and retrieving envelope tracking information."""
        # Register envelope
        tracked = await default_tracker.track(
            sample_envelope,
            # target=FameAddress("target@/service"),
            timeout_ms=5000,
            expected_response_type=FameResponseType.ACK,
            meta={"test": "metadata"},
        )

        assert tracked.envelope_id == sample_envelope.id
        assert tracked.correlation_id == sample_envelope.corr_id
        assert tracked.expect_ack is True
        assert tracked.expect_reply is False
        assert tracked.meta["test"] == "metadata"

        # Retrieve envelope
        retrieved = await default_tracker.get_tracked_envelope(sample_envelope.id)
        assert retrieved is not None
        assert retrieved.envelope_id == sample_envelope.id
        assert retrieved.status == EnvelopeStatus.PENDING

        # List pending
        pending = await default_tracker.list_pending()
        assert len(pending) == 1
        assert pending[0].envelope_id == sample_envelope.id

    @pytest.mark.asyncio
    async def test_ack_handling(self, default_tracker, sample_envelope):
        """Test ACK handling functionality."""
        # Register envelope that expects ACK
        await default_tracker.track(
            sample_envelope,
            # target=FameAddress("target@/service"),
            timeout_ms=5000,
            expected_response_type=FameResponseType.ACK,
        )

        # Create ACK envelope
        ack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ok=True, code="ok", ref_id=sample_envelope.id),
            corr_id=sample_envelope.corr_id,
        )

        # Process ACK
        await default_tracker.on_ack(ack_envelope)

        # Check status
        retrieved = await default_tracker.get_tracked_envelope(sample_envelope.id)
        assert retrieved is not None
        assert retrieved.status == EnvelopeStatus.ACKED

    @pytest.mark.asyncio
    async def test_recovery_functionality(self, default_tracker, sample_envelope):
        """Test recovery of pending envelopes after restart."""
        # Register envelope
        await default_tracker.track(
            sample_envelope,
            # target=FameAddress("target@/service"),
            timeout_ms=5000,
            expected_response_type=FameResponseType.ACK,
        )

        # Verify it's pending
        pending_before = await default_tracker.list_pending()
        assert len(pending_before) == 1

        # Simulate restart by calling recover_pending
        await default_tracker.recover_pending()

        # Should still be pending
        pending_after = await default_tracker.list_pending()
        assert len(pending_after) == 1
        assert pending_after[0].envelope_id == sample_envelope.id

    @pytest.mark.asyncio
    async def test_await_reply_functionality(self, default_tracker, sample_envelope):
        """Test await_reply functionality."""
        # Register envelope that expects reply
        await default_tracker.track(
            sample_envelope,
            # target=FameAddress("target@/service"),
            timeout_ms=5000,
            expected_response_type=FameResponseType.REPLY,
        )

        # Create a task to await the reply
        async def await_reply_task():
            return await default_tracker.await_reply(sample_envelope.id)

        reply_task = asyncio.create_task(await_reply_task())

        # Give the task a moment to start
        await asyncio.sleep(0.01)

        # Reply should still be pending
        assert not reply_task.done()

        # Send the reply
        reply_payload = {"result": "success", "data": "test_data"}
        reply_envelope = create_fame_envelope(
            frame=DataFrame(payload=reply_payload),
            corr_id=sample_envelope.corr_id,
        )
        # Get the tracked envelope for the reply
        tracked = await default_tracker.get_tracked_envelope(sample_envelope.id)
        assert tracked is not None
        await default_tracker.on_reply(reply_envelope, tracked)

        # Reply task should now be complete
        result = await reply_task
        assert result.frame.payload == reply_payload

        # Check status
        retrieved = await default_tracker.get_tracked_envelope(sample_envelope.id)
        assert retrieved is not None
        assert retrieved.status == EnvelopeStatus.RESPONDED


class TestDefaultDeliveryTrackerWithStorage:
    """Test the default envelope tracker with storage provider."""

    @pytest.mark.asyncio
    async def test_tracker_creation(self, in_memory_storage):
        """Test creating a storage-backed tracker."""

        factory = DefaultDeliveryTrackerFactory()
        tracker = await factory.create(storage_provider=in_memory_storage)
        assert tracker is not None
        await tracker.cleanup()

    @pytest.mark.asyncio
    async def test_register_and_retrieve_envelope(self, storage_tracker, sample_envelope):
        """Test registering and retrieving envelope tracking information."""
        try:
            # Register envelope
            tracked = await storage_tracker.track(
                sample_envelope,
                # target=FameAddress("target@/service"),
                timeout_ms=5000,
                expected_response_type=FameResponseType.ACK,
                meta={"test": "metadata"},
            )

            assert tracked.envelope_id == sample_envelope.id
            assert tracked.correlation_id == sample_envelope.corr_id
            assert tracked.expect_ack is True
            assert tracked.expect_reply is False
            assert tracked.meta["test"] == "metadata"

            # Retrieve envelope
            retrieved = await storage_tracker.get_tracked_envelope(sample_envelope.id)
            assert retrieved is not None
            assert retrieved.envelope_id == sample_envelope.id
            assert retrieved.status == EnvelopeStatus.PENDING

            # List pending
            pending = await storage_tracker.list_pending()
            assert len(pending) == 1
            assert pending[0].envelope_id == sample_envelope.id

        finally:
            await storage_tracker.cleanup()

    @pytest.mark.asyncio
    async def test_ack_handling(self, storage_tracker, sample_envelope):
        """Test ack handling."""
        try:
            # Register envelope expecting ack
            await storage_tracker.track(
                sample_envelope,
                timeout_ms=5000,
                expected_response_type=FameResponseType.ACK,
            )

            # Start waiting for ack
            ack_task = asyncio.create_task(storage_tracker.await_ack(sample_envelope.id))

            # Give it a moment to set up
            await asyncio.sleep(0.01)

            # Send ack
            ack_envelope = create_fame_envelope(
                frame=DeliveryAckFrame(ok=True, code="ok", ref_id=sample_envelope.id),
                corr_id=sample_envelope.corr_id,
            )
            await storage_tracker.on_ack(ack_envelope)

            # Await should complete
            await ack_task

            # Check status updated
            tracked = await storage_tracker.get_tracked_envelope(sample_envelope.id)
            assert tracked.status == EnvelopeStatus.ACKED

        finally:
            await storage_tracker.cleanup()

    @pytest.mark.asyncio
    async def test_nack_handling(self, storage_tracker, sample_envelope):
        """Test nack handling."""
        try:
            # Register envelope expecting ack
            await storage_tracker.track(
                sample_envelope,
                timeout_ms=5000,
                expected_response_type=FameResponseType.ACK,
            )

            # Start waiting for ack
            ack_task = asyncio.create_task(storage_tracker.await_ack(sample_envelope.id))

            # Give it a moment to set up
            await asyncio.sleep(0.01)

            # Send nack
            nack_envelope = create_fame_envelope(
                frame=DeliveryAckFrame(
                    ok=False, code="delivery_failed", reason="test nack reason", ref_id=sample_envelope.id
                ),
                corr_id=sample_envelope.corr_id,
            )
            await storage_tracker.on_nack(nack_envelope)

            # Await should raise exception
            with pytest.raises(RuntimeError, match="test nack reason"):
                await ack_task

            # Check status updated
            tracked = await storage_tracker.get_tracked_envelope(sample_envelope.id)
            assert tracked.status == EnvelopeStatus.NACKED
            assert tracked.meta["nack_reason"] == "test nack reason"

        finally:
            await storage_tracker.cleanup()

    @pytest.mark.asyncio
    async def test_reply_handling(self, storage_tracker, sample_envelope):
        """Test reply handling."""
        try:
            # Register envelope expecting reply
            await storage_tracker.track(
                sample_envelope,
                timeout_ms=5000,
                expected_response_type=FameResponseType.REPLY,
            )

            # Send reply
            reply_envelope = create_fame_envelope(
                frame=DataFrame(payload={"result": "success"}),
                corr_id=sample_envelope.corr_id,
            )
            # Get the tracked envelope for the reply
            tracked = await storage_tracker.get_tracked_envelope(sample_envelope.id)
            assert tracked is not None
            await storage_tracker.on_reply(reply_envelope, tracked)

            # Check status updated
            tracked = await storage_tracker.get_tracked_envelope(sample_envelope.id)
            assert tracked.status == EnvelopeStatus.RESPONDED

        finally:
            await storage_tracker.cleanup()

    @pytest.mark.asyncio
    async def test_timeout_handling(self, storage_tracker, sample_envelope):
        """Test timeout handling."""
        try:
            # Register envelope with short timeout
            await storage_tracker.track(
                sample_envelope,
                expected_response_type=FameResponseType.ACK,
                timeout_ms=50,  # 50ms timeout
            )

            # Wait for timeout
            await asyncio.sleep(0.1)  # 100ms

            # Check status updated to timed out
            tracked = await storage_tracker.get_tracked_envelope(sample_envelope.id)
            assert tracked.status == EnvelopeStatus.TIMED_OUT

        finally:
            await storage_tracker.cleanup()

    @pytest.mark.asyncio
    async def test_event_handlers(self, in_memory_storage, sample_envelope):
        """Test event handler integration."""
        # Create mock event handlers
        event_handler = MagicMock()
        event_handler.on_envelope_acked = AsyncMock()
        event_handler.on_envelope_nacked = AsyncMock()
        event_handler.on_envelope_replied = AsyncMock()
        event_handler.on_envelope_timeout = AsyncMock()

        retry_handler = MagicMock()
        retry_handler.on_retry_needed = AsyncMock()

        factory = DefaultDeliveryTrackerFactory()
        tracker = await factory.create(
            storage_provider=in_memory_storage,
            event_handler=event_handler,
            retry_handler=retry_handler,
        )

        # Manually initialize the tracker like a node would
        mock_node = MagicMock()
        await tracker.on_node_initialized(mock_node)

        try:
            # Register envelope
            await tracker.track(
                sample_envelope,
                timeout_ms=5000,
                expected_response_type=FameResponseType.ACK,
            )

            # Test ack event
            ack_envelope = create_fame_envelope(
                frame=DeliveryAckFrame(ok=True, code="ok", ref_id=sample_envelope.id),
                corr_id=sample_envelope.corr_id,
            )
            await tracker.on_ack(ack_envelope)
            event_handler.on_envelope_acked.assert_called_once()

            # Reset and test nack event with a new envelope
            event_handler.reset_mock()
            nack_envelope = create_fame_envelope(
                frame=DataFrame(payload={"test": "data2"}),
                corr_id="test-2",
            )
            await tracker.track(
                nack_envelope,
                timeout_ms=5000,
                expected_response_type=FameResponseType.ACK,
            )

            nack_env = create_fame_envelope(
                frame=DeliveryAckFrame(
                    ok=False, code="delivery_failed", reason="test reason", ref_id=nack_envelope.id
                ),
                corr_id=nack_envelope.corr_id,
            )
            await tracker.on_nack(nack_env)
            event_handler.on_envelope_nacked.assert_called_once()

        finally:
            await tracker.cleanup()

    @pytest.mark.asyncio
    async def test_recovery(self, in_memory_storage, sample_envelope):
        """Test recovery of pending envelopes."""

        factory = DefaultDeliveryTrackerFactory()
        tracker = await factory.create(storage_provider=in_memory_storage)

        # Manually initialize the tracker like a node would
        mock_node = MagicMock()
        await tracker.on_node_initialized(mock_node)

        try:
            # Register envelope
            await tracker.track(
                sample_envelope,
                timeout_ms=60000,  # Long timeout to avoid immediate timeout
                expected_response_type=FameResponseType.ACK,
            )

            # Verify it's pending
            pending_before = await tracker.list_pending()
            assert len(pending_before) == 1

            # Create new tracker with same storage (simulating restart)
            new_factory = DefaultDeliveryTrackerFactory()
            new_tracker = await new_factory.create(storage_provider=in_memory_storage)

            # Initialize the new tracker too
            mock_node2 = MagicMock()
            await new_tracker.on_node_initialized(mock_node2)

            try:
                # Should see the pending envelope in storage
                pending_before_recovery = await new_tracker.list_pending()
                assert len(pending_before_recovery) == 1  # Data is persisted

                # Recover pending envelopes
                await new_tracker.recover_pending()

                # Should be able to handle ack
                ack_envelope = create_fame_envelope(
                    frame=DeliveryAckFrame(ok=True, code="ok", ref_id=sample_envelope.id),
                    corr_id=sample_envelope.corr_id,
                )
                await new_tracker.on_ack(ack_envelope)

                # Check status updated
                tracked = await new_tracker.get_tracked_envelope(sample_envelope.id)
                assert tracked.status == EnvelopeStatus.ACKED  # type: ignore

            finally:
                await new_tracker.cleanup()

        finally:
            await tracker.cleanup()


class TestTrackedEnvelope:
    """Test the TrackedEnvelope model used for both domain and persistence."""

    def test_tracked_envelope_serialization(self):
        """Test that TrackedEnvelope can be serialized and deserialized."""
        # Create a sample original envelope
        original_envelope = create_fame_envelope(
            frame=DataFrame(payload={"test": "data"}),
            to=FameAddress("service@/test"),
            corr_id="test-corr",
        )
        # Override the ID for consistency
        original_envelope.id = "test-id"

        tracked = TrackedEnvelope(
            timeout_at_ms=1234567890000,
            overall_timeout_at_ms=1234567890000,
            expected_response_type=FameResponseType.NONE,
            created_at_ms=1234567889000,
            attempt=1,
            status=EnvelopeStatus.ACKED,
            meta={"test": "metadata"},
            original_envelope=original_envelope,
        )

        # Test Pydantic serialization (what KeyValueStore uses)
        data = tracked.model_dump()
        restored = TrackedEnvelope.model_validate(data)

        assert restored.envelope_id == "test-id"
        assert restored.correlation_id == "test-corr"
        assert restored.timeout_at_ms == 1234567890000
        assert restored.expect_ack is False
        assert restored.expect_reply is False
        assert restored.created_at_ms == 1234567889000
        assert restored.attempt == 1
        assert restored.status == EnvelopeStatus.ACKED
        assert restored.meta["test"] == "metadata"

    def test_tracked_envelope_with_original_envelope(self):
        """Test that TrackedEnvelope can store and restore original envelopes."""
        from naylence.fame.core import DataFrame, create_fame_envelope

        # Create an original envelope
        original = create_fame_envelope(
            frame=DataFrame(payload={"test": "data"}),
            to=FameAddress("test@/service"),
        )

        tracked = TrackedEnvelope(
            timeout_at_ms=1234567890000,
            overall_timeout_at_ms=1234567890000,
            expected_response_type=FameResponseType.ACK,
            created_at_ms=1234567889000,
            original_envelope=original,  # Store the original envelope
        )

        # Test serialization with nested envelope
        data = tracked.model_dump()
        restored = TrackedEnvelope.model_validate(data)

        assert restored.envelope_id == original.id
        assert restored.original_envelope is not None
        assert restored.original_envelope.id == original.id
        assert restored.original_envelope.frame.payload == {"test": "data"}  # type: ignore


class TestDeliveryTrackerFactory:
    """Test the factory pattern for envelope trackers."""

    @pytest.mark.asyncio
    async def test_default_tracker_factory_direct(self):
        """Test creating default tracker via factory directly."""
        from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

        storage_provider = InMemoryStorageProvider()
        factory = DefaultDeliveryTrackerFactory()

        tracker = await factory.create(storage_provider=storage_provider)

        assert tracker is not None
        assert isinstance(tracker, DefaultDeliveryTracker)
        await tracker.cleanup()

    @pytest.mark.asyncio
    async def test_default_tracker_factory_with_storage_provider(self):
        """Test creating default tracker via factory with storage provider."""

        storage_provider = InMemoryStorageProvider()
        factory = DefaultDeliveryTrackerFactory()
        config = DefaultDeliveryTrackerConfig(namespace="test_tracker")

        tracker = await factory.create(config, storage_provider=storage_provider)

        assert tracker is not None
        assert isinstance(tracker, DefaultDeliveryTracker)
        await tracker.cleanup()

    @pytest.mark.asyncio
    async def test_factory_defaults_to_in_memory(self):
        """Test that factory defaults to in-memory storage when neither provider nor kv_store is given."""

        factory = DefaultDeliveryTrackerFactory()
        config = DefaultDeliveryTrackerConfig()

        # Should not raise an error - should default to in-memory
        tracker = await factory.create(config)
        assert tracker is not None
        assert isinstance(tracker, DefaultDeliveryTracker)
        await tracker.cleanup()
