#!/usr/bin/env python3
"""Additional edge case tests to push DefaultDeliveryTracker coverage above 95%."""

import asyncio
import pytest
import time
from unittest.mock import Mock, AsyncMock, patch
from naylence.fame.delivery.default_delivery_tracker import DefaultDeliveryTracker
from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.node.node_like import NodeLike
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.util.envelope_context import FameEnvelope
from naylence.fame.delivery.delivery_tracker import TrackedEnvelope, EnvelopeStatus
from naylence.fame.core import DeliveryAckFrame, FameDeliveryContext, DataFrame, FameResponseType, create_fame_envelope


@pytest.fixture
async def tracker():
    """Create a DefaultDeliveryTracker for testing."""
    storage_provider = InMemoryStorageProvider()
    
    tracker = DefaultDeliveryTracker(storage_provider)
    
    # Mock the _node attribute before starting
    node = Mock(spec=NodeLike)
    node.id = "test-node"
    node.envelope_factory = Mock()
    node.envelope_factory.create_envelope = Mock()
    
    # Start the tracker
    await tracker.on_node_initialized(node)
    await tracker.on_node_started(node)
    
    return tracker


@pytest.mark.asyncio
class TestDeliveryTrackerEdgeCases:
    """Test edge cases to improve coverage."""

    async def test_wait_for_pending_acks_exception_handling(self, tracker):
        """Test exception handling in _wait_for_pending_acks method."""
        # Create a mock envelope with future that will raise an exception
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # Add to outbox
        current_time_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            timeout_at_ms=current_time_ms + 5000,
            overall_timeout_at_ms=current_time_ms + 5000,
            expected_response_type=FameResponseType.NONE,
            created_at_ms=current_time_ms,
            attempt=1,
            status=EnvelopeStatus.PENDING,
            original_envelope=envelope,
        )
        await tracker._outbox.set(envelope.id, tracked)
        
        # Create a future that will raise an exception
        future = asyncio.Future()
        future.set_exception(RuntimeError("Test exception"))
        
        # Add to pending acks
        tracker._ack_futures[envelope.id] = future
        
        # This should handle the exception gracefully
        await tracker._wait_for_pending_acks()

    async def test_wait_for_pending_acks_already_expired(self, tracker):
        """Test behavior when envelope timeout has already expired."""
        # Create a mock envelope with an expired timeout
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # Add to outbox with expired timeout
        current_time_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            timeout_at_ms=current_time_ms - 1000,  # 1 second ago (expired)
            overall_timeout_at_ms=current_time_ms - 1000,
            expected_response_type=FameResponseType.NONE,
            created_at_ms=current_time_ms - 2000,
            attempt=1,
            status=EnvelopeStatus.PENDING,
            original_envelope=envelope,
        )
        await tracker._outbox.set(envelope.id, tracked)
        
        # Create a future
        future = asyncio.Future()
        tracker._ack_futures[envelope.id] = future
        
        # This should handle the expired timeout
        await tracker._wait_for_pending_acks()

    async def test_wait_for_pending_acks_outer_exception(self, tracker):
        """Test outer exception handling in _wait_for_pending_acks."""
        # Create a mock envelope
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # Create a future
        future = asyncio.Future()
        tracker._ack_futures[envelope.id] = future
        
        # Mock the outbox.get method to raise an exception
        original_get = tracker._outbox.get
        
        async def mock_get(envelope_id):
            if envelope_id == envelope.id:
                raise RuntimeError("Outbox error")
            return await original_get(envelope_id)
        
        tracker._outbox.get = mock_get
        
        # This should handle the outer exception gracefully
        await tracker._wait_for_pending_acks()

    async def test_on_ack_nack_frames(self, tracker):
        """Test handling of ACK and NACK frames."""
        # First, create and track an original envelope
        original_envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # Track it to establish correlation
        await tracker.track(original_envelope, timeout_ms=5000, expected_response_type=FameResponseType.ACK)
        
        # Test NACK frame - use the correlation ID from the tracked envelope
        nack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ok=False, ref_id=original_envelope.id),
            to="node@test-destination",
            corr_id=original_envelope.id  # Use the original envelope ID as correlation
        )
        
        # Mock the on_nack method
        tracker.on_nack = AsyncMock()
        
        # Call on_envelope_delivered with NACK
        result = await tracker.on_envelope_delivered("test-inbox", nack_envelope)
        
        # Verify on_nack was called
        tracker.on_nack.assert_called_once_with(nack_envelope, None)

    async def test_on_correlated_message_path(self, tracker):
        """Test the correlated message handling path."""
        # Create envelope with correlation ID but not a delivery ack
        corr_envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination",
            corr_id="correlation-123"
        )
        
        # Mock the on_correlated_message method
        tracker.on_correlated_message = AsyncMock(return_value=Mock())
        
        # Call on_envelope_delivered
        result = await tracker.on_envelope_delivered("test-inbox", corr_envelope)
        
        # Verify on_correlated_message was called
        tracker.on_correlated_message.assert_called_once_with("test-inbox", corr_envelope, None)

    async def test_on_envelope_handled_sets_status(self, tracker):
        """Test that on_envelope_handled sets the status correctly."""
        # Create a tracked envelope
        original_envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # Create a tracked envelope
        current_time_ms = int(time.time() * 1000)
        tracked = TrackedEnvelope(
            timeout_at_ms=current_time_ms + 5000,
            overall_timeout_at_ms=current_time_ms + 5000,
            expected_response_type=FameResponseType.NONE,
            created_at_ms=current_time_ms,
            attempt=1,
            status=EnvelopeStatus.PENDING,
            original_envelope=original_envelope,
        )
        
        # Add to inbox
        await tracker._inbox.set(original_envelope.id, tracked)
        
        # Call on_envelope_handled
        await tracker.on_envelope_handled("test-inbox", tracked)
        
        # Verify status was updated
        assert tracked.status == EnvelopeStatus.HANDLED
        
        # Verify it was saved back to inbox
        saved_tracked = await tracker._inbox.get(original_envelope.id)
        assert saved_tracked.status == EnvelopeStatus.HANDLED

    async def test_on_heartbeat_sent_display(self, tracker):
        """Test the display functionality in on_heartbeat_sent."""
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # This method should complete without error
        await tracker.on_heartbeat_sent(envelope)

    async def test_error_scenarios_in_ack_handling(self, tracker):
        """Test various error scenarios in ACK handling."""
        # Create an envelope for ACK handling
        original_envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to="node@test-destination"
        )
        
        # Create ACK envelope
        ack_envelope = create_fame_envelope(
            frame=DeliveryAckFrame(ok=True, ref_id="original-envelope"),
            to="node@test-destination"
        )
        
        # Test when the original envelope is not in pending_acks
        # This should handle gracefully
        result = await tracker.on_envelope_delivered("test-inbox", ack_envelope)
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
