"""
Test to verify that FameDeliveryContext is preserved through sink services.
This tests the end-to-end flow: publish -> sink -> fanout broker -> subscriber.
"""

import asyncio
from typing import Optional

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.service.in_memory_sink_service import InMemorySinkService
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.tracking.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerFactory,
)


@pytest.mark.asyncio
async def test_context_preservation_through_sink():
    """Test that delivery context is preserved through sink service fanout."""
    received_envelopes = []
    received_contexts = []

    async def sink_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handler that captures both envelope and context."""
        received_envelopes.append(envelope)
        received_contexts.append(context)
        print("Sink handler received:")
        print(f"  📨 Envelope ID: {envelope.id}")
        print(f"  📦 Payload: {envelope.frame.payload}")
        if context:
            print(f"  🔧 Context: origin={context.origin_type}, system={context.from_system_id}")
        else:
            print("  🔧 Context: None")
        return None

    # Create fabric manually like in the stress test
    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
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

    fabric = InProcessFameFabric(node=node)
    sink_service = InMemorySinkService(binding_manager=node.binding_manager, deliver=fabric.send)
    await fabric.serve(sink_service, "sink")

    try:
        # Create a sink
        sink_address = await fabric.create_sink("test-sink")
        print(f"📍 Created sink at: {sink_address}")

        # Subscribe to the sink with our handler that receives envelope and context
        subscriber_address = await node.listen("test-subscriber", sink_handler)
        await sink_service.subscribe(
            {
                "sink_address": sink_address,
                "subscriber_address": subscriber_address,
            }
        )
        print("🔔 Subscribed to sink")

        # Wait a moment for subscription to be active
        await asyncio.sleep(0.1)

        # Send a message to the sink with a specific delivery context
        test_envelope = FameEnvelope(
            id=generate_id(),
            to=sink_address,
            frame=DataFrame(payload={"message": "context preservation test"}, codec="json"),
        )

        # The fabric.send should create a delivery context automatically
        print("📤 Sending message to sink...")
        await fabric.send(test_envelope)

        # Wait for message processing
        await asyncio.sleep(0.5)

        # Verify results
        print("\n📋 Results:")
        print(f"  Messages received: {len(received_envelopes)}")
        print(f"  Contexts received: {len(received_contexts)}")

        assert len(received_envelopes) == 1, f"Expected 1 message, got {len(received_envelopes)}"

        envelope = received_envelopes[0]
        context = received_contexts[0]

        print(f"  ✅ Received envelope: {envelope.id}")
        print(f"  📦 Payload: {envelope.frame.payload}")

        assert context is not None, "Context should be preserved"
        print("  ✅ Context preserved!")
        print(f"     Origin: {context.origin_type}")
        print(f"     System ID: {context.from_system_id}")

        assert context.origin_type == DeliveryOriginType.LOCAL, (
            f"Expected LOCAL origin, got {context.origin_type}"
        )
        print("  ✅ Origin type is LOCAL as expected")

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_context_preservation_multiple_subscribers():
    """Test context preservation with multiple subscribers."""
    subscriber1_received = []
    subscriber2_received = []

    async def subscriber1_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        subscriber1_received.append((envelope, context))
        print(f"Subscriber 1 received: {envelope.frame.payload} with context: {context is not None}")
        return None

    async def subscriber2_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        subscriber2_received.append((envelope, context))
        print(f"Subscriber 2 received: {envelope.frame.payload} with context: {context is not None}")
        return None

    # Create fabric manually
    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
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

    fabric = InProcessFameFabric(node=node)
    sink_service = InMemorySinkService(binding_manager=node.binding_manager, deliver=fabric.send)
    await fabric.serve(sink_service, "sink")

    try:
        # Create a sink
        sink_address = await fabric.create_sink("multi-test-sink")
        print(f"📍 Created sink at: {sink_address}")

        # Subscribe with multiple handlers that receive envelope and context
        subscriber1_address = await node.listen("subscriber-1", subscriber1_handler)
        subscriber2_address = await node.listen("subscriber-2", subscriber2_handler)

        await sink_service.subscribe(
            {
                "sink_address": sink_address,
                "subscriber_address": subscriber1_address,
            }
        )
        await sink_service.subscribe(
            {
                "sink_address": sink_address,
                "subscriber_address": subscriber2_address,
            }
        )
        print("🔔 Subscribed two handlers to sink")

        await asyncio.sleep(0.1)

        # Send a message
        test_envelope = FameEnvelope(
            id=generate_id(),
            to=sink_address,
            frame=DataFrame(payload={"test": "multi-subscriber"}, codec="json"),
        )

        print("📤 Sending message to sink...")
        await fabric.send(test_envelope)

        await asyncio.sleep(0.5)

        # Verify both subscribers received the message with context
        print(f"\n📋 Subscriber 1 results: {len(subscriber1_received)} messages")
        print(f"📋 Subscriber 2 results: {len(subscriber2_received)} messages")

        assert len(subscriber1_received) == 1, (
            f"Subscriber 1: Expected 1 message, got {len(subscriber1_received)}"
        )
        assert len(subscriber2_received) == 1, (
            f"Subscriber 2: Expected 1 message, got {len(subscriber2_received)}"
        )

        envelope1, context1 = subscriber1_received[0]
        envelope2, context2 = subscriber2_received[0]

        assert context1 is not None, "Subscriber 1: Context should be preserved"
        assert context1.origin_type == DeliveryOriginType.LOCAL, (
            "Subscriber 1: Context should have LOCAL origin"
        )
        print("  ✅ Subscriber 1: Context preserved")

        assert context2 is not None, "Subscriber 2: Context should be preserved"
        assert context2.origin_type == DeliveryOriginType.LOCAL, (
            "Subscriber 2: Context should have LOCAL origin"
        )
        print("  ✅ Subscriber 2: Context preserved")

    finally:
        await node.stop()
