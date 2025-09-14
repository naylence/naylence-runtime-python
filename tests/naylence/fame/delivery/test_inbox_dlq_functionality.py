#!/usr/bin/env python3
"""
Test script to verify the inbox DLQ functionality is working correctly.
"""

import asyncio
import time

import pytest

from naylence.fame.core import DataFrame, FameAddress, FameResponseType, create_fame_envelope
from naylence.fame.delivery.default_delivery_tracker import DefaultDeliveryTracker
from naylence.fame.delivery.delivery_tracker import EnvelopeStatus, MailboxType, TrackedEnvelope
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


class MockNode:
    """Simple mock node for testing."""

    def __init__(self, node_id: str):
        self.id = node_id
        self.sid = f"{node_id}-session"
        self.physical_path = f"/path/to/{node_id}"


@pytest.mark.asyncio
async def test_inbox_dlq_functionality():
    """Test that inbox DLQ functionality works end-to-end."""

    # Create storage provider and delivery tracker
    storage_provider = InMemoryStorageProvider()
    tracker = DefaultDeliveryTracker(storage_provider)

    # Initialize with a mock node
    node = MockNode("test-node")
    await tracker.on_node_initialized(node)

    # Create a test envelope
    envelope = create_fame_envelope(
        frame=DataFrame(payload={"message": "test message"}),
        to=FameAddress("test-service@test-node"),
    )
    envelope.id = "test-envelope-1"

    # Create a tracked envelope (simulating inbound delivery)
    tracked = TrackedEnvelope(
        envelope_id=envelope.id,
        original_envelope=envelope,
        service_name="test-service",
        status=EnvelopeStatus.RECEIVED,
        timeout_at_ms=int(time.time() * 1000) + 60000,  # 1 minute from now
        overall_timeout_at_ms=int(time.time() * 1000) + 60000,
        expected_response_type=FameResponseType.ACK,
        created_at_ms=int(time.time() * 1000),
        mailbox_type=MailboxType.INBOX,
        attempt=3,  # Simulate we've tried 3 times
        meta={},
    )

    # Test 1: Add to inbox DLQ
    await tracker.add_to_inbox_dlq(tracked, reason="Maximum retries exceeded")

    # Test 2: Get from inbox DLQ
    dlq_envelope = await tracker.get_from_inbox_dlq(envelope.id)
    assert dlq_envelope is not None, "Envelope should be in inbox DLQ"
    assert dlq_envelope.meta.get("dlq") is True, "DLQ flag should be set"
    assert dlq_envelope.meta.get("dlq_reason") == "Maximum retries exceeded", "DLQ reason should be set"
    assert "dead_lettered_at_ms" in dlq_envelope.meta, "Timestamp should be set"

    # Test 3: List inbox DLQ
    dlq_list = await tracker.list_inbox_dlq()
    assert len(dlq_list) == 1, "Inbox DLQ should contain one envelope"
    assert dlq_list[0].envelope_id == envelope.id, "Inbox DLQ should contain our envelope"

    # Test 4: Test on_envelope_handle_failed with final failure
    # Create another envelope for testing final failure
    envelope2 = create_fame_envelope(
        frame=DataFrame(payload={"message": "test message 2"}),
        to=FameAddress("test-service@test-node"),
    )
    envelope2.id = "test-envelope-2"

    tracked2 = TrackedEnvelope(
        envelope_id=envelope2.id,
        original_envelope=envelope2,
        service_name="test-service",
        status=EnvelopeStatus.RECEIVED,
        timeout_at_ms=int(time.time() * 1000) + 60000,
        overall_timeout_at_ms=int(time.time() * 1000) + 60000,
        expected_response_type=FameResponseType.ACK,
        created_at_ms=int(time.time() * 1000),
        mailbox_type=MailboxType.INBOX,
        attempt=5,
        meta={},
    )

    # First add to inbox
    await tracker.on_envelope_delivered("test-service", envelope2)

    # Now simulate final failure - this should move to DLQ
    await tracker.on_envelope_handle_failed(
        "test-service", tracked2, error=Exception("Handler failed completely"), is_final_failure=True
    )

    # Verify it's in inbox DLQ
    dlq_list = await tracker.list_inbox_dlq()
    assert len(dlq_list) == 2, "Inbox DLQ should now contain two envelopes"
    dlq_envelope2 = await tracker.get_from_inbox_dlq(envelope2.id)
    assert dlq_envelope2 is not None, "Second envelope should be in inbox DLQ"
    assert dlq_envelope2.status == EnvelopeStatus.FAILED_TO_HANDLE, "Status should be FAILED_TO_HANDLE"

    # Test 5: Purge inbox DLQ with predicate
    deleted_count = await tracker.purge_inbox_dlq(predicate=lambda env: env.envelope_id == envelope.id)
    assert deleted_count == 1, "Should have deleted one envelope"

    dlq_list = await tracker.list_inbox_dlq()
    assert len(dlq_list) == 1, "Inbox DLQ should now contain one envelope"
    assert dlq_list[0].envelope_id == envelope2.id, "Should contain only the second envelope"

    # Test 6: Purge all inbox DLQ
    deleted_count = await tracker.purge_inbox_dlq()
    assert deleted_count == 1, "Should have deleted one envelope"

    dlq_list = await tracker.list_inbox_dlq()
    assert len(dlq_list) == 0, "Inbox DLQ should be empty"


@pytest.mark.asyncio
async def test_inbox_dlq_empty_operations():
    """Test DLQ operations when DLQ is empty or uninitialized."""

    # Create storage provider and delivery tracker
    storage_provider = InMemoryStorageProvider()
    tracker = DefaultDeliveryTracker(storage_provider)

    # Before initialization, DLQ operations should handle gracefully
    result = await tracker.get_from_inbox_dlq("nonexistent")
    assert result is None, "Should return None for uninitialized DLQ"

    result = await tracker.list_inbox_dlq()
    assert result == [], "Should return empty list for uninitialized DLQ"

    result = await tracker.purge_inbox_dlq()
    assert result == 0, "Should return 0 for uninitialized DLQ"

    # Initialize with a mock node
    node = MockNode("test-node")
    await tracker.on_node_initialized(node)

    # Now test empty but initialized DLQ
    result = await tracker.get_from_inbox_dlq("nonexistent")
    assert result is None, "Should return None for empty DLQ"

    result = await tracker.list_inbox_dlq()
    assert result == [], "Should return empty list for empty DLQ"

    result = await tracker.purge_inbox_dlq()
    assert result == 0, "Should return 0 for empty DLQ"


@pytest.mark.asyncio
async def test_inbox_dlq_predicate_filtering():
    """Test that DLQ predicate filtering works correctly."""

    # Create storage provider and delivery tracker
    storage_provider = InMemoryStorageProvider()
    tracker = DefaultDeliveryTracker(storage_provider)

    # Initialize with a mock node
    node = MockNode("test-node")
    await tracker.on_node_initialized(node)

    # Create multiple test envelopes
    envelopes = []
    for i in range(3):
        envelope = create_fame_envelope(
            frame=DataFrame(payload={"message": f"test message {i}"}),
            to=FameAddress("test-service@test-node"),
        )
        envelope.id = f"test-envelope-{i}"

        tracked = TrackedEnvelope(
            envelope_id=envelope.id,
            original_envelope=envelope,
            service_name="test-service",
            status=EnvelopeStatus.RECEIVED,
            timeout_at_ms=int(time.time() * 1000) + 60000,
            overall_timeout_at_ms=int(time.time() * 1000) + 60000,
            expected_response_type=FameResponseType.ACK,
            created_at_ms=int(time.time() * 1000),
            mailbox_type=MailboxType.INBOX,
            attempt=i + 1,  # Different attempt counts
            meta={},
        )

        await tracker.add_to_inbox_dlq(tracked, reason=f"Reason {i}")
        envelopes.append(envelope)

    # Verify all envelopes are in DLQ
    dlq_list = await tracker.list_inbox_dlq()
    assert len(dlq_list) == 3, "Should have 3 envelopes in DLQ"

    # Test predicate filtering - delete only envelopes with attempt > 2
    deleted_count = await tracker.purge_inbox_dlq(predicate=lambda env: env.attempt > 2)
    assert deleted_count == 1, "Should have deleted 1 envelope (attempt=3)"

    # Verify remaining envelopes
    dlq_list = await tracker.list_inbox_dlq()
    assert len(dlq_list) == 2, "Should have 2 envelopes remaining"
    remaining_attempts = [env.attempt for env in dlq_list]
    assert 1 in remaining_attempts and 2 in remaining_attempts, "Should have attempts 1 and 2 remaining"


if __name__ == "__main__":
    asyncio.run(test_inbox_dlq_functionality())
    print("🎉 All inbox DLQ functionality tests passed!")
