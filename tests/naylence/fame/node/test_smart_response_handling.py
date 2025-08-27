#!/usr/bin/env python3
"""
Test to verify smart response handling in EnvelopeListenerManager.
This tests that the listener manager properly creates context and sets metadata
when handlers return FameMessageResponse with incomplete information.
"""

import asyncio
from typing import Optional

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameMessageResponse,
    generate_id,
)
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_smart_response_context_creation():
    """Test that missing response context is automatically created."""
    captured_deliveries = []

    async def test_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handler that returns a response without context."""
        print(f"🔧 Handler called with envelope: {envelope.id}")
        print(f"🔧 Handler reply_to: {envelope.reply_to}")

        # Create a response envelope without context
        response_envelope = FameEnvelope(
            id=generate_id(),
            to=envelope.reply_to or FameAddress("test-reply@/test"),
            frame=DataFrame(payload={"response": "test"}, codec="json"),
        )

        print(f"🔧 Handler returning response: {response_envelope.id}")

        # Return FameMessageResponse with NO context (should be auto-created)
        return FameMessageResponse(envelope=response_envelope, context=None)

    # Create a node
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import (
        DefaultDeliveryTrackerFactory,
    )

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
    node = FameNode(
        env_context=None,
        requested_logicals=["test.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    await node.start()

    # Wrap deliver to capture what gets delivered
    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        captured_deliveries.append((envelope, context))
        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    # Also wrap the listener manager's _deliver method
    listener_manager = node._envelope_listener_manager
    original_listener_deliver = listener_manager._deliver

    async def capturing_listener_deliver(
        envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ):
        captured_deliveries.append((envelope, context))
        return await original_listener_deliver(envelope, context)

    listener_manager._deliver = capturing_listener_deliver

    try:
        # Create a listener
        listener_address = await node.listen("smart-response-service", test_handler)
        print(f"📍 Created listener at: {listener_address}")

        await asyncio.sleep(0.1)

        # Send a request with context
        request_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM,
            from_system_id="external-system",
        )

        request_envelope = FameEnvelope(
            id=generate_id(),
            to=listener_address,
            reply_to=FameAddress("test-reply@/test"),  # Properly formatted Fame address
            frame=DataFrame(payload={"request": "test"}, codec="json"),
        )

        print("📤 Sending request...")
        await node.deliver(request_envelope, request_context)

        # Wait for processing
        await asyncio.sleep(0.5)

        # Verify the response was delivered with auto-created context
        print(f"\n📋 Results: {len(captured_deliveries)} deliveries captured")

        # We should have 2 deliveries: original request + auto-generated response
        assert len(captured_deliveries) >= 1, (
            f"Expected at least 1 delivery, got {len(captured_deliveries)}"
        )

        # Find the response delivery (the one that's not our original request)
        response_delivery = None
        for envelope, context in captured_deliveries:
            if envelope.id != request_envelope.id:  # Not the original request
                response_delivery = (envelope, context)
                break

        assert response_delivery is not None, "Should have found a response delivery"

        response_envelope, response_context = response_delivery

        # Verify context was auto-created
        assert response_context is not None, "Response context should have been auto-created"
        assert response_context.origin_type == DeliveryOriginType.LOCAL, "Response should have LOCAL origin"
        assert response_context.from_system_id is not None, "Response should have system ID"

        # Verify metadata was auto-set in context (not envelope)
        assert response_context.meta is not None, "Response context should have metadata"
        assert response_context.meta.get("message-type") == "response", (
            "Should have response message-type in context"
        )
        assert response_context.meta.get("response-to-id") == request_envelope.id, (
            "Should link back to original request in context"
        )

        print("✅ Smart response handling working correctly!")
        print(f"   Auto-created context: origin={response_context.origin_type}")
        print(f"   Auto-set metadata in context: {response_context.meta}")

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_smart_response_preserves_existing_context():
    """Test that existing response context and metadata are preserved."""
    captured_deliveries = []

    async def test_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handler that returns a response WITH context and metadata."""
        # Create a response envelope with existing metadata
        response_envelope = FameEnvelope(
            id=generate_id(),
            to=envelope.reply_to or FameAddress("test-reply"),
            frame=DataFrame(payload={"response": "test"}, codec="json"),
            meta={"message-type": "custom-response", "custom-field": "preserved"},
        )

        # Create explicit context
        response_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM,  # Different from default LOCAL
            from_system_id="custom-system-id",
        )

        return FameMessageResponse(envelope=response_envelope, context=response_context)

    # Create a node
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import (
        DefaultDeliveryTrackerFactory,
    )

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
    node = FameNode(
        env_context=None,
        requested_logicals=["test2.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    await node.start()

    # Wrap deliver to capture what gets delivered
    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        captured_deliveries.append((envelope, context))
        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    # Also wrap the listener manager's _deliver method
    listener_manager = node._envelope_listener_manager
    original_listener_deliver = listener_manager._deliver

    async def capturing_listener_deliver(
        envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ):
        captured_deliveries.append((envelope, context))
        return await original_listener_deliver(envelope, context)

    listener_manager._deliver = capturing_listener_deliver

    try:
        # Create a listener
        listener_address = await node.listen("preserve-response-service", test_handler)

        await asyncio.sleep(0.1)

        # Send a request
        request_envelope = FameEnvelope(
            id=generate_id(),
            to=listener_address,
            reply_to=FameAddress("test-reply@/test2"),  # Properly formatted Fame address
            frame=DataFrame(payload={"request": "test"}, codec="json"),
        )

        await node.deliver(request_envelope)
        await asyncio.sleep(0.5)

        # Find the response delivery
        response_delivery = None
        for envelope, context in captured_deliveries:
            if envelope.id != request_envelope.id:
                response_delivery = (envelope, context)
                break

        assert response_delivery is not None, "Should have found a response delivery"

        response_envelope, response_context = response_delivery

        # Verify existing context was preserved
        assert response_context is not None, "Response context should be preserved"
        assert response_context.origin_type == DeliveryOriginType.UPSTREAM, "Should preserve custom origin"
        assert response_context.from_system_id == "custom-system-id", "Should preserve custom system ID"

        # Verify context metadata was set (should override message-type to "response")
        assert response_context.meta is not None, "Response context should have metadata"
        assert response_context.meta.get("message-type") == "response", (
            "Should override to response message-type in context"
        )
        assert response_context.meta.get("response-to-id") == request_envelope.id, (
            "Should link back to original request in context"
        )

        # Verify envelope metadata is preserved as-is (system no longer modifies envelope metadata)
        assert response_envelope.meta is not None, "Response envelope should have original metadata"
        assert response_envelope.meta.get("message-type") == "custom-response", (
            "Should preserve original envelope message-type"
        )
        assert response_envelope.meta.get("custom-field") == "preserved", (
            "Should preserve other envelope metadata fields"
        )

        print("✅ Existing context and metadata preserved correctly!")
        print(
            f"   Preserved context: origin={response_context.origin_type}, "
            "system={response_context.from_system_id}"
        )
        print(f"   Context metadata: {response_context.meta}")
        print(f"   Envelope metadata: {response_envelope.meta}")

    finally:
        await node.stop()
