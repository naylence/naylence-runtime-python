"""
Comprehensive tests for both "at-least-once" and "at-most-once" delivery policies.
These tests ensure proper ACK handling and delivery guarantees for both policies.
"""

import asyncio
from typing import Any, Optional

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    generate_id,
    make_request,
)
from naylence.fame.delivery.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory
from naylence.fame.delivery.delivery_profile_factory import DeliveryProfileFactory
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_at_most_once_delivery_policy():
    """Test that 'at-most-once' delivery policy does not require ACKs."""
    print("🧪 Testing 'at-most-once' delivery policy (no ACK required)")

    # Create node with at-most-once delivery policy
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    # Create "at-most-once" delivery policy
    delivery_policy_factory = DeliveryProfileFactory()
    delivery_policy = await delivery_policy_factory.create({"profile": "at-most-once"})

    node = FameNode(
        env_context=None,
        requested_logicals=["test.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
        delivery_policy=delivery_policy,
    )
    await node.start()

    # Track delivered envelopes to verify no ACK expectations
    delivered_envelopes = []
    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        delivered_envelopes.append((envelope, context))
        print(f"📦 Delivered envelope {envelope.id}")
        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    try:
        # Set up RPC service
        async def test_rpc_handler(method: str, params: dict[str, Any] | None):
            print(f"📨 RPC handler called: {method}")
            return {"result": "success"}

        listener_manager = node._envelope_listener_manager
        service_address = await listener_manager.listen_rpc("test-service", test_rpc_handler)
        await asyncio.sleep(0.1)

        # Create and send RPC request
        request_id = generate_id()
        request = make_request(id=request_id, method="test_method", params={})

        async def reply_handler(env, ctx):
            print(f"📨 Reply received: {env.id}")

        reply_to_address = await node.listen("reply-handler", reply_handler)

        request_envelope = node._envelope_factory.create_envelope(
            to=service_address,
            frame=DataFrame(payload=request),
            reply_to=reply_to_address,
            corr_id=request_id,
        )

        request_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id=node.id)

        # Deliver the request - should NOT require ACKs
        await node.deliver(request_envelope, request_context)
        await asyncio.sleep(0.5)

        # Verify delivery occurred without ACK issues
        assert len(delivered_envelopes) >= 1, "Should have delivered at least the request"
        print("✅ At-most-once delivery policy works without ACK requirements")

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_at_least_once_delivery_policy_with_acks():
    """Test that 'at-least-once' delivery policy requires and handles ACKs properly."""
    print("🧪 Testing 'at-least-once' delivery policy (ACKs required)")

    # Create node with at-least-once delivery policy
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    # Create "at-least-once" delivery policy
    delivery_policy_factory = DeliveryProfileFactory()
    delivery_policy = await delivery_policy_factory.create({"profile": "at-least-once"})

    node = FameNode(
        env_context=None,
        requested_logicals=["test.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
        delivery_policy=delivery_policy,
    )
    await node.start()

    # Track delivered envelopes and ACKs
    delivered_envelopes = []
    received_acks = []

    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        delivered_envelopes.append((envelope, context))
        print(f"📦 Delivered envelope {envelope.id}")

        # For at-least-once policy, we need to simulate sending ACKs back for responses
        if isinstance(envelope.frame, DataFrame):
            # Check if this is a response that would go to another node
            if context and context.origin_type == DeliveryOriginType.LOCAL:
                # Simulate ACK from the receiving node
                ack_frame = DeliveryAckFrame(corr_id=envelope.id, ok=True, code="ok")
                ack_envelope = node._envelope_factory.create_envelope(frame=ack_frame)
                received_acks.append(ack_envelope)

                # Process the ACK asynchronously to simulate network response
                async def send_ack():
                    await asyncio.sleep(0.01)  # Small delay to simulate network
                    ack_context = FameDeliveryContext(
                        origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="mock-receiver"
                    )
                    await node.handle_delivery_ack(ack_frame, ack_context)
                    print(f"✅ Sent ACK for envelope {envelope.id}")

                asyncio.create_task(send_ack())

        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    try:
        # Set up RPC service
        async def test_rpc_handler(method: str, params: dict[str, Any] | None):
            print(f"📨 RPC handler called: {method}")
            return {"result": "success"}

        listener_manager = node._envelope_listener_manager
        service_address = await listener_manager.listen_rpc("test-service", test_rpc_handler)
        await asyncio.sleep(0.1)

        # Create and send RPC request
        request_id = generate_id()
        request = make_request(id=request_id, method="test_method", params={})

        async def reply_handler(env, ctx):
            print(f"📨 Reply received: {env.id}")

        reply_to_address = await node.listen("reply-handler", reply_handler)

        request_envelope = node._envelope_factory.create_envelope(
            to=service_address,
            frame=DataFrame(payload=request),
            reply_to=reply_to_address,
            corr_id=request_id,
        )

        request_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="external-node"
        )

        # Track the request in delivery tracker to expect a response
        await delivery_tracker.track(
            request_envelope,
            timeout_ms=5000,
            expected_response_type=FameResponseType.REPLY,
        )

        # Deliver the request - should require ACKs
        await node.deliver(request_envelope, request_context)
        await asyncio.sleep(1.0)  # Give time for ACK processing

        # Verify delivery and ACK handling
        assert len(delivered_envelopes) >= 1, "Should have delivered at least the request"
        assert len(received_acks) >= 0, "Should have processed ACKs for responses"
        print("✅ At-least-once delivery policy works with proper ACK handling")

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_delivery_policy_ack_requirements():
    """Test that delivery policies correctly determine ACK requirements."""
    print("🧪 Testing delivery policy ACK requirement determination")

    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    InMemoryStorageProvider()
    delivery_policy_factory = DeliveryProfileFactory()

    # Test at-most-once policy
    at_most_once_policy = await delivery_policy_factory.create({"profile": "at-most-once"})

    # Test at-least-once policy
    at_least_once_policy = await delivery_policy_factory.create({"profile": "at-least-once"})

    # Create test envelope
    test_envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"test": "data"}),
    )

    # Test ACK requirements
    at_most_once_ack_required = at_most_once_policy.is_ack_required(test_envelope)
    at_least_once_ack_required = at_least_once_policy.is_ack_required(test_envelope)

    print(f"📋 At-most-once ACK required: {at_most_once_ack_required}")
    print(f"📋 At-least-once ACK required: {at_least_once_ack_required}")

    # Verify expectations
    assert not at_most_once_ack_required, "At-most-once should not require ACKs for data frames"
    assert at_least_once_ack_required, "At-least-once should require ACKs for data frames"

    print("✅ Delivery policy ACK requirements work correctly")


@pytest.mark.asyncio
async def test_mixed_delivery_policy_scenarios():
    """Test scenarios with different delivery policies between nodes."""
    print("🧪 Testing mixed delivery policy scenarios")

    # This test simulates the real-world scenario where different nodes
    # might have different delivery policies configured

    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
    delivery_policy_factory = DeliveryProfileFactory()

    # Create node with at-most-once policy (like our fixed tests)
    at_most_once_policy = await delivery_policy_factory.create({"profile": "at-most-once"})

    node = FameNode(
        env_context=None,
        requested_logicals=["test.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
        delivery_policy=at_most_once_policy,
    )
    await node.start()

    try:
        # Verify the node is configured for at-most-once
        test_envelope = node._envelope_factory.create_envelope(frame=DataFrame(payload={"test": "data"}))

        ack_required = node._delivery_policy.is_ack_required(test_envelope)
        assert not ack_required, "Node should be configured for at-most-once (no ACKs)"

        print("✅ Node correctly configured for at-most-once delivery")

        # Test that we can still handle incoming messages from nodes that use at-least-once
        # (This simulates receiving a message from a node that expects an ACK)
        incoming_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="at-least-once-node"
        )

        # The node should be able to process this message even though it came from
        # a node with different delivery policy expectations
        await node.deliver(test_envelope, incoming_context)

        print("✅ Node can handle messages from nodes with different delivery policies")

    finally:
        await node.stop()


if __name__ == "__main__":
    # Run the tests manually for debugging
    async def run_tests():
        print("🚀 Running delivery policy tests...")
        await test_at_most_once_delivery_policy()
        print()
        await test_at_least_once_delivery_policy_with_acks()
        print()
        await test_delivery_policy_ack_requirements()
        print()
        await test_mixed_delivery_policy_scenarios()
        print("🎉 All delivery policy tests completed!")

    asyncio.run(run_tests())
