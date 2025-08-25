#!/usr/bin/env python3
"""
Test to verify that FameDeliveryContext is preserved in local delivery.
This tests the basic node-level context preservation functionality.
"""

from typing import Optional

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_context_preservation():
    """Test that delivery context is properly preserved in local delivery."""
    received_envelope = None
    received_context = None

    async def test_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handler that captures both envelope and context."""
        nonlocal received_envelope, received_context
        received_envelope = envelope
        received_context = context
        print(f"Handler received envelope: {envelope.id}")
        if context:
            print(f"Handler received context: {context}")
            print(f"  - Origin type: {context.origin_type}")
            print(f"  - From system ID: {context.from_system_id}")
        else:
            print("Handler received context: None")
        # Don't return anything to avoid triggering reply processing

    # Create a node and start it
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

    try:
        print("1. Testing context preservation...")

        # Create a listener
        listener_address = await node.listen("test-service", test_handler)
        print(f"Created listener at address: {listener_address}")

        # Create an envelope
        test_envelope = FameEnvelope(
            id=generate_id(),
            to=listener_address,
            frame=DataFrame(payload={"test": "context preservation"}, codec="json"),
        )

        # Create a delivery context
        test_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL, from_system_id="test-system-123"
        )

        # Deliver with context
        await node.deliver(test_envelope, test_context)

        # Wait for processing
        import asyncio

        await asyncio.sleep(0.1)

        # Verify that both envelope and context were received
        assert received_envelope is not None, "Envelope should have been received"
        assert received_envelope.id == test_envelope.id, "Should receive the same envelope"

        assert received_context is not None, "Context should have been preserved"
        assert received_context.origin_type == DeliveryOriginType.LOCAL, "Origin type should be preserved"
        assert received_context.from_system_id == "test-system-123", "System ID should be preserved"

        print("✅ SUCCESS: Delivery context was properly preserved!")

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_backward_compatibility():
    """Test that handlers still work when no context is provided."""
    received_envelope = None
    received_context = None

    async def test_handler(envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handler that captures both envelope and context."""
        nonlocal received_envelope, received_context
        received_envelope = envelope
        received_context = context
        print(f"Handler received envelope: {envelope.id}")
        print(f"Handler received context: {context}")
        # Don't return anything to avoid triggering reply processing

    # Create a node and start it
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

    try:
        print("2. Testing backward compatibility...")

        # Create a listener
        listener_address = await node.listen("test-service-2", test_handler)
        print(f"Created listener at address: {listener_address}")

        # Create an envelope
        test_envelope = FameEnvelope(
            id=generate_id(),
            to=listener_address,
            frame=DataFrame(payload={"test": "backward compatibility"}, codec="json"),
        )

        # Deliver WITHOUT context (backward compatibility)
        await node.deliver(test_envelope)

        # Wait for processing
        import asyncio

        await asyncio.sleep(0.1)

        # Verify that envelope was received but context is None
        assert received_envelope is not None, "Envelope should have been received"
        assert received_envelope.id == test_envelope.id, "Should receive the same envelope"
        assert received_context is None, "Context should be None for backward compatibility"

        print("✅ SUCCESS: Backward compatibility maintained!")

    finally:
        await node.stop()
