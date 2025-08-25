"""Test that responses to encrypted messages maintain proper crypto levels."""

import asyncio
from typing import Any, Optional

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
    make_request,
)
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_encrypted_request_encrypted_response():
    """Test that when an encrypted request is received, the response is also encrypted."""
    response_contexts = []

    async def test_rpc_handler(method: str, params: dict[str, Any] | None):
        """RPC handler that returns a simple result."""
        print(f"📨 RPC handler called: {method} with params: {params}")
        return {"result": f"processed {method}"}

    # Create a node
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

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

    # Capture delivered messages to check response contexts
    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        print(f"🔍 Deliver called with envelope {envelope.id}, meta: {envelope.meta}")
        if context:
            print(
                f"🔍 Context: origin={context.origin_type}, "
                f"crypto_level={context.security.inbound_crypto_level if context.security else None}"
            )
            # Check for response message
            if context.meta and context.meta.get("message-type") == "response":
                response_contexts.append(context)
                print(
                    f"📤 Captured response context! crypto_level for response: "
                    f"{context.security.inbound_crypto_level if context.security else None}"
                )
        else:
            print("🔍 No context provided")
        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    # Also wrap the listener manager's _deliver method to see what's happening
    listener_manager = node._envelope_listener_manager
    original_listener_deliver = listener_manager._deliver

    async def capturing_listener_deliver(
        envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ):
        print(
            f"🎯 EnvelopeListenerManager._deliver called with envelope {envelope.id}, meta: {envelope.meta}"
        )
        if context:
            print(
                f"🎯 Context: origin={context.origin_type}, "
                f"crypto_level={context.security.inbound_crypto_level if context.security else None}"
            )
            if context.meta and context.meta.get("message-type") == "response":
                response_contexts.append(context)
                print(
                    f"📤 Captured response context from listener manager! "
                    f"crypto_level: {context.security.inbound_crypto_level if context.security else None}"
                )
        else:
            print("🎯 No context provided to listener manager")
        return await original_listener_deliver(envelope, context)

    listener_manager._deliver = capturing_listener_deliver

    try:
        # Set up RPC listener
        service_address = await listener_manager.listen_rpc("math", test_rpc_handler)
        print(f"📍 RPC service listening at: {service_address}")

        await asyncio.sleep(0.1)  # Let listener start

        # Simulate the scenario from the logs: encrypted request (SEALED) should result in
        # encrypted response
        request_id = generate_id()
        request = make_request(id=request_id, method="test_method", params={"data": "test"})

        # Create a proper reply-to address that we can listen to
        async def reply_handler(env, ctx):
            print(f"📨 Reply received: {env.id}")

        reply_to_address = await node.listen("test-reply-handler", reply_handler)

        request_envelope = node._envelope_factory.create_envelope(
            to=service_address,
            frame=DataFrame(corr_id=request_id, payload=request),
            reply_to=reply_to_address,
            corr_id=request_id,
        )

        # Create delivery context with SEALED crypto level (like in the logs)
        # This simulates receiving an encrypted message from an external system
        from naylence.fame.core.protocol.delivery_context import SecurityContext

        request_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM,
            from_system_id="external-system-123",
            security=SecurityContext(inbound_crypto_level=CryptoLevel.SEALED),  # The request was encrypted
        )

        print("📤 Sending encrypted RPC request with context:")
        print(f"   Origin: {request_context.origin_type}")
        print(f"   System ID: {request_context.from_system_id}")
        print(
            f"   Inbound crypto level: "
            f"{request_context.security.inbound_crypto_level if request_context.security else None}"
        )

        # Deliver the request
        await node.deliver(request_envelope, request_context)

        # Wait for response processing
        await asyncio.sleep(0.5)

        # Verify results
        print("\n📋 Results:")
        print(f"   Response contexts captured: {len(response_contexts)}")

        assert len(response_contexts) == 1, f"Expected 1 response context, got {len(response_contexts)}"

        response_context = response_contexts[0]

        print("✅ Response context captured:")
        print(f"   Origin: {response_context.origin_type}")
        print(f"   System ID: {response_context.from_system_id}")
        print(
            f"   Inbound crypto level: "
            f"{response_context.security.inbound_crypto_level if response_context.security else None}"
        )

        # Verify inheritance - the key test!
        assert response_context.origin_type == DeliveryOriginType.LOCAL, (
            f"Expected LOCAL origin for response, got {response_context.origin_type}"
        )
        print("✅ Response origin is LOCAL as expected")

        # The critical assertion: when we receive a SEALED request, the response should also be SEALED
        response_crypto_level = (
            response_context.security.inbound_crypto_level if response_context.security else None
        )
        assert response_crypto_level == CryptoLevel.SEALED, (
            f"Response should inherit SEALED crypto level from encrypted request: "
            f"expected {CryptoLevel.SEALED}, got {response_crypto_level}"
        )
        print(
            "✅ Response will be encrypted (SEALED) as expected - matching the incoming encrypted request!"
        )

        print("\n🎯 SUCCESS: Encrypted request (SEALED) → Encrypted response (SEALED)")
        print("   This ensures end-to-end encryption is preserved in request-response flows")

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_plaintext_request_plaintext_response():
    """Test that plaintext requests result in plaintext responses."""
    response_contexts = []

    async def test_rpc_handler(method: str, params: dict[str, Any] | None):
        return {"result": "processed"}

    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

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

    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        if context and context.meta and context.meta.get("message-type") == "response":
            response_contexts.append(context)
            print(
                f"📤 Captured plaintext response context! "
                f"crypto_level: {context.security.inbound_crypto_level if context.security else None}"
            )
        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    # Also wrap the listener manager's _deliver method to see what's happening
    listener_manager = node._envelope_listener_manager
    original_listener_deliver = listener_manager._deliver

    async def capturing_listener_deliver(
        envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ):
        if context and context.meta and context.meta.get("message-type") == "response":
            response_contexts.append(context)
            print(
                f"📤 Captured plaintext response context from listener manager! "
                f"crypto_level: {context.security.inbound_crypto_level if context.security else None}"
            )
        return await original_listener_deliver(envelope, context)

    listener_manager._deliver = capturing_listener_deliver

    try:
        service_address = await listener_manager.listen_rpc("test-service", test_rpc_handler)

        await asyncio.sleep(0.1)

        # Create a plaintext request
        request_id = generate_id()
        request = make_request(id=request_id, method="test_method", params={"data": "test"})

        async def reply_handler(env, ctx):
            pass

        reply_to_address = await node.listen("test-reply-handler", reply_handler)

        request_envelope = node._envelope_factory.create_envelope(
            to=service_address,
            frame=DataFrame(corr_id=request_id, payload=request),
            reply_to=reply_to_address,
            corr_id=request_id,
        )

        # Create delivery context with PLAINTEXT crypto level
        from naylence.fame.core.protocol.delivery_context import SecurityContext

        request_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM,
            from_system_id="external-system-123",
            security=SecurityContext(
                inbound_crypto_level=CryptoLevel.PLAINTEXT
            ),  # The request was plaintext
        )

        print("📤 Sending plaintext RPC request")

        await node.deliver(request_envelope, request_context)
        await asyncio.sleep(0.5)

        assert len(response_contexts) == 1, f"Expected 1 response context, got {len(response_contexts)}"

        response_context = response_contexts[0]

        # Plaintext request should result in plaintext response
        response_crypto_level = (
            response_context.security.inbound_crypto_level if response_context.security else None
        )
        assert response_crypto_level == CryptoLevel.PLAINTEXT, (
            f"Response should inherit PLAINTEXT crypto level: "
            f"expected {CryptoLevel.PLAINTEXT}, got {response_crypto_level}"
        )

        print("✅ Plaintext request → Plaintext response (as expected)")

    finally:
        await node.stop()
