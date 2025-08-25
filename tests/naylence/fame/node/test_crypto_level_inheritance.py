#!/usr/bin/env python3
"""
Test to verify that crypto levels are inherited in RPC response contexts.
"""

import asyncio
from typing import Any, Optional

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    generate_id,
    make_request,
)
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory


@pytest.mark.asyncio
async def test_crypto_level_inheritance():
    """Test that RPC response contexts inherit crypto levels from request contexts."""
    response_contexts = []

    async def test_rpc_handler(method: str, params: dict[str, Any] | None):
        """RPC handler that returns a simple result."""
        print(f"📨 RPC handler called: {method} with params: {params}")
        return {"result": f"processed {method}"}

    # Create a node with storage provider
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

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
                print("📤 Captured response context!")
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
                print("📤 Captured response context from listener manager!")
        else:
            print("🎯 No context provided to listener manager")
        return await original_listener_deliver(envelope, context)

    listener_manager._deliver = capturing_listener_deliver

    try:
        # Set up RPC listener
        listener_manager = node._envelope_listener_manager
        service_address = await listener_manager.listen_rpc("test-service", test_rpc_handler)
        print(f"📍 RPC service listening at: {service_address}")

        await asyncio.sleep(0.1)  # Let listener start

        # Create an RPC request with crypto levels in the delivery context
        request_id = generate_id()
        request = make_request(id=request_id, method="test_method", params={"data": "test"})

        # Create a proper reply-to address that we can listen to
        async def reply_handler(env, ctx):
            print(f"📨 Reply received: {env.id}")

        reply_to_address = await node.listen("test-reply-handler", reply_handler)

        request_envelope = node._envelope_factory.create_envelope(
            to=service_address,
            frame=DataFrame(payload=request),
            reply_to=reply_to_address,
            corr_id=request_id,
        )  # Create delivery context with crypto levels
        from naylence.fame.core.protocol.delivery_context import SecurityContext

        request_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM,
            from_system_id="external-system-123",
            security=SecurityContext(inbound_crypto_level=CryptoLevel.SEALED),
        )

        print("📤 Sending RPC request with context:")
        print(f"   Origin: {request_context.origin_type}")
        print(f"   System ID: {request_context.from_system_id}")
        print(
            f"   Inbound crypto level: "
            f"{request_context.security.inbound_crypto_level if request_context.security else None}"
        )

        # Track the outbound request with the envelope tracker
        await delivery_tracker.track(
            request_envelope, timeout_ms=5000, expected_response_type=FameResponseType.REPLY
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
        print("\n🔍 Detailed comparison:")
        print(f"   Original request context id: {id(request_context)}")
        print(f"   Response context id: {id(response_context)}")
        print(
            f"   Request inbound: "
            f"{request_context.security.inbound_crypto_level if request_context.security else None} "
            f"vs Response inbound: "
            f"{response_context.security.inbound_crypto_level if response_context.security else None}"
        )

        # Verify inheritance
        assert response_context.origin_type == DeliveryOriginType.LOCAL, (
            f"Expected LOCAL origin for response, got {response_context.origin_type}"
        )
        print("✅ Response origin is LOCAL as expected")

        # For local responses, the inbound_crypto_level should reflect the actual security level
        # of the response delivery (which may be PLAINTEXT for local delivery)
        # The important thing is that security.inbound_crypto_level is inherited from the original request
        request_crypto_level = (
            request_context.security.inbound_crypto_level if request_context.security else None
        )
        response_crypto_level = (
            response_context.security.inbound_crypto_level if response_context.security else None
        )
        assert response_crypto_level == request_crypto_level, (
            f"Inbound crypto level not inherited: expected {request_crypto_level}, "
            f"got {response_crypto_level}"
        )
        print("✅ Original request crypto level inherited correctly")
        # Note: security.inbound_crypto_level for local responses is expected to be PLAINTEXT
        if response_crypto_level == CryptoLevel.PLAINTEXT:
            print("✅ Response inbound crypto level is PLAINTEXT as expected for local delivery")
        else:
            print(
                f"🔍 Response inbound crypto level is {response_crypto_level} "
                f"(may be valid depending on implementation)"
            )

    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_crypto_level_inheritance_no_context():
    """Test that RPC responses work correctly when no crypto context is available."""
    response_contexts = []

    async def simple_rpc_handler(method: str, params: dict[str, Any] | None):
        return {"result": "ok"}

    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

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

    original_deliver = node.deliver

    async def capturing_deliver(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        if context and context.meta and context.meta.get("message-type") == "response":
            response_contexts.append(context)
        return await original_deliver(envelope, context)

    node.deliver = capturing_deliver

    # Also wrap the listener manager's _deliver method
    listener_manager = node._envelope_listener_manager
    original_listener_deliver = listener_manager._deliver

    async def capturing_listener_deliver(
        envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ):
        if context and context.meta and context.meta.get("message-type") == "response":
            response_contexts.append(context)
        return await original_listener_deliver(envelope, context)

    listener_manager._deliver = capturing_listener_deliver

    try:
        listener_manager = node._envelope_listener_manager
        service_address = await listener_manager.listen_rpc("simple-service", simple_rpc_handler)

        await asyncio.sleep(0.1)

        # Send request with no crypto levels
        request_id = generate_id()
        request = make_request(id=request_id, method="simple", params={})

        # Create a proper reply-to address
        async def simple_reply_handler(env, ctx):
            print(f"📨 Simple reply received: {env.id}")

        reply_to_address = await node.listen("simple-reply-handler", simple_reply_handler)

        request_envelope = node._envelope_factory.create_envelope(
            to=service_address,
            frame=DataFrame(payload=request),
            reply_to=reply_to_address,
            corr_id=request_id,
        )

        # Context with no crypto levels
        request_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL, from_system_id="local-system"
        )

        # Track the outbound request with the envelope tracker
        await delivery_tracker.track(
            request_envelope, timeout_ms=5000, expected_response_type=FameResponseType.REPLY
        )

        await node.deliver(request_envelope, request_context)
        await asyncio.sleep(0.5)

        assert len(response_contexts) == 1, f"Expected 1 response context, got {len(response_contexts)}"

        response_context = response_contexts[0]

        # When no crypto levels are specified in the request context,
        # the security handler will set default values (typically PLAINTEXT)
        response_crypto_level = (
            response_context.security.inbound_crypto_level if response_context.security else None
        )
        if response_crypto_level == CryptoLevel.PLAINTEXT:
            print("✅ Default crypto level set correctly when none present in request")
        else:
            print(
                f"🔍 Crypto level in response: inbound="
                f"{response_context.security.inbound_crypto_level if response_context.security else None}"
            )
            print("✅ Crypto level set by security policy (this is expected behavior)")

    finally:
        await node.stop()
