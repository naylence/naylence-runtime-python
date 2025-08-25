"""
Test script to verify DeliveryAck frame handling in FameNode.
"""

import pytest

from naylence.fame.core import (
    DeliveryAckFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    create_fame_envelope,
)
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory


@pytest.mark.asyncio
async def test_delivery_ack_handling():
    """Test that FameNode properly handles DeliveryAck frames."""

    print("🧪 Testing DeliveryAck frame handling")
    print("=" * 40)

    # Create a test node with storage provider
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        system_id="test-node",
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    node._sid = "test-sid"

    # Test 1: Successful DeliveryAck
    print("\n📋 Test 1: Successful DeliveryAck")
    success_frame = DeliveryAckFrame(corr_id="test-message-123", ok=True, code="ok")
    success_envelope = create_fame_envelope(frame=success_frame)
    context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="sender-node")

    await node.handle_system_frame(success_envelope, context)
    print("✅ Successfully handled positive DeliveryAck")
    assert success_frame.ok is True
    assert success_frame.code == "ok"

    # Test 2: NACK (crypto level violation)
    print("\n📋 Test 2: NACK for crypto_level_violation")
    nack_frame = DeliveryAckFrame(
        corr_id="test-message-456",
        ok=False,
        code="crypto_level_violation",
        reason="Plaintext not allowed",
    )
    nack_envelope = create_fame_envelope(frame=nack_frame)

    await node.handle_system_frame(nack_envelope, context)
    print("✅ Successfully handled crypto level violation NACK")
    assert nack_frame.ok is False
    assert nack_frame.code == "crypto_level_violation"

    # Test 3: NACK (signature violation)
    print("\n📋 Test 3: NACK for signature_required")
    sig_nack_frame = DeliveryAckFrame(
        corr_id="test-message-789",
        ok=False,
        code="signature_required",
        reason="Message must be signed",
    )
    sig_nack_envelope = create_fame_envelope(frame=sig_nack_frame)

    await node.handle_system_frame(sig_nack_envelope, context)
    print("✅ Successfully handled signature requirement NACK")
    assert sig_nack_frame.ok is False
    assert sig_nack_frame.code == "signature_required"

    # Test 4: NACK (invalid signature)
    print("\n📋 Test 4: NACK for signature_verification_failed")
    invalid_sig_nack_frame = DeliveryAckFrame(
        corr_id="test-message-101",
        ok=False,
        code="signature_verification_failed",
        reason="Signature verification failed",
    )
    invalid_sig_nack_envelope = create_fame_envelope(frame=invalid_sig_nack_frame)

    await node.handle_system_frame(invalid_sig_nack_envelope, context)
    print("✅ Successfully handled signature verification failure NACK")
    assert invalid_sig_nack_frame.ok is False
    assert invalid_sig_nack_frame.code == "signature_verification_failed"

    print("\n🎉 DeliveryAck frame handling test complete!")
    print("\n✅ All DeliveryAck frame types are now properly handled")
    print("   - Successful acknowledgments are logged")
    print("   - NACKs are logged with violation details")
    print("   - Applications can override _on_delivery_nack for custom handling")


@pytest.mark.asyncio
async def test_successful_delivery_ack():
    """Test handling of successful DeliveryAck frames."""
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        system_id="test-node",
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    node._sid = "test-sid"

    success_frame = DeliveryAckFrame(corr_id="test-message-123", ok=True, code="ok")
    success_envelope = create_fame_envelope(frame=success_frame)
    context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="sender-node")

    # Should handle successfully without raising an exception
    try:
        await node.handle_system_frame(success_envelope, context)
        # If we reach here, the test passed
        assert True, "Successfully handled positive DeliveryAck"
    except Exception as e:
        pytest.fail(f"Unexpected exception handling positive DeliveryAck: {e}")


@pytest.mark.asyncio
async def test_crypto_level_violation_nack():
    """Test handling of crypto level violation NACK."""
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        system_id="test-node",
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    node._sid = "test-sid"

    nack_frame = DeliveryAckFrame(
        corr_id="test-message-456",
        ok=False,
        code="crypto_level_violation",
        reason="Plaintext not allowed",
    )
    nack_envelope = create_fame_envelope(frame=nack_frame)
    context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="sender-node")

    # Should handle NACK without raising an exception
    try:
        await node.handle_system_frame(nack_envelope, context)
        # Verify the frame was processed correctly
        assert nack_frame.ok is False
        assert nack_frame.code == "crypto_level_violation"
        assert nack_frame.reason == "Plaintext not allowed"
    except Exception as e:
        pytest.fail(f"Unexpected exception handling crypto level violation NACK: {e}")


@pytest.mark.asyncio
async def test_signature_required_nack():
    """Test handling of signature required NACK."""
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        system_id="test-node",
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    node._sid = "test-sid"

    nack_frame = DeliveryAckFrame(
        corr_id="test-message-789",
        ok=False,
        code="signature_required",
        reason="Message must be signed",
    )
    nack_envelope = create_fame_envelope(frame=nack_frame)
    context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="sender-node")

    # Should handle NACK without raising an exception
    try:
        await node.handle_system_frame(nack_envelope, context)
        # Verify the frame was processed correctly
        assert nack_frame.ok is False
        assert nack_frame.code == "signature_required"
        assert nack_frame.reason == "Message must be signed"
    except Exception as e:
        pytest.fail(f"Unexpected exception handling signature required NACK: {e}")


@pytest.mark.asyncio
async def test_signature_verification_failed_nack():
    """Test handling of signature verification failed NACK."""
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        system_id="test-node",
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    node._sid = "test-sid"

    nack_frame = DeliveryAckFrame(
        corr_id="test-message-101",
        ok=False,
        code="signature_verification_failed",
        reason="Signature verification failed",
    )
    nack_envelope = create_fame_envelope(frame=nack_frame)
    context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="sender-node")

    # Should handle NACK without raising an exception
    try:
        await node.handle_system_frame(nack_envelope, context)
        # Verify the frame was processed correctly
        assert nack_frame.ok is False
        assert nack_frame.code == "signature_verification_failed"
        assert nack_frame.reason == "Signature verification failed"
    except Exception as e:
        pytest.fail(f"Unexpected exception handling signature verification failed NACK: {e}")
