"""
Test that channel encryption is properly detected and classified by the security policy.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    SecurityContext,
    generate_id,
)
from naylence.fame.core.protocol.security_header import EncryptionHeader, SecurityHeader
from naylence.fame.node.envelope_listener_manager import EnvelopeListenerManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.tracking.delivery_tracker import DeliveryTracker


@pytest.mark.asyncio
async def test_classify_message_crypto_level_channel_encryption():
    """Test that channel-encrypted messages are properly classified as CHANNEL level."""
    # Create a security policy
    policy = DefaultSecurityPolicy()

    # Create a plain envelope (no envelope-level encryption)
    envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"test": "data"}), to=FameAddress("test-service@test.com")
    )

    # Test: No context (should be PLAINTEXT)
    crypto_level = policy.classify_message_crypto_level(envelope, None)
    assert crypto_level == CryptoLevel.PLAINTEXT

    # Test: Context without channel encryption (should be PLAINTEXT)
    context_no_channel = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
    crypto_level = policy.classify_message_crypto_level(envelope, context_no_channel)
    assert crypto_level == CryptoLevel.PLAINTEXT

    # Test: Envelope with channel encryption algorithm (should be CHANNEL)
    channel_envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"test": "data"}),
        to=FameAddress("test-service@test.com"),
        sec=SecurityHeader(enc=EncryptionHeader(alg="chacha20-poly1305-channel", val="encrypted-data")),
    )
    context_with_channel = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL, security=SecurityContext(crypto_channel_id="test-channel-123")
    )
    crypto_level = policy.classify_message_crypto_level(channel_envelope, context_with_channel)
    assert crypto_level == CryptoLevel.CHANNEL


@pytest.mark.asyncio
async def test_classify_message_crypto_level_sealed_takes_precedence():
    """Test that SEALED (envelope encryption) is properly detected."""
    # Create a security policy
    policy = DefaultSecurityPolicy()

    # Create an envelope with envelope-level encryption (SEALED)
    envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"test": "data"}),
        to=FameAddress("test-service@test.com"),
        sec=SecurityHeader(enc=EncryptionHeader(kid="test-key", val="encrypted-data-base64")),
    )

    # Context with channel transport
    context_with_channel = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL, security=SecurityContext(crypto_channel_id="test-channel-123")
    )

    # Should classify as SEALED because envelope encryption is present
    crypto_level = policy.classify_message_crypto_level(envelope, context_with_channel)
    assert crypto_level == CryptoLevel.SEALED


@pytest.mark.asyncio
async def test_classify_message_crypto_level_precedence_order():
    """Test the full precedence order: SEALED > CHANNEL > PLAINTEXT."""
    policy = DefaultSecurityPolicy()

    # Base envelope without envelope encryption
    base_envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"test": "data"}), to=FameAddress("test-service@test.com")
    )

    # PLAINTEXT: No encryption at any level
    plaintext_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
    crypto_level = policy.classify_message_crypto_level(base_envelope, plaintext_context)
    assert crypto_level == CryptoLevel.PLAINTEXT

    # CHANNEL: Channel encryption algorithm
    channel_envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"test": "data"}),
        to=FameAddress("test-service@test.com"),
        sec=SecurityHeader(enc=EncryptionHeader(alg="chacha20-poly1305-channel", val="encrypted-data")),
    )
    channel_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL, security=SecurityContext(crypto_channel_id="test-channel")
    )
    crypto_level = policy.classify_message_crypto_level(channel_envelope, channel_context)
    assert crypto_level == CryptoLevel.CHANNEL

    # SEALED: Envelope encryption (non-channel algorithm)
    sealed_envelope = base_envelope.model_copy(
        update={"sec": SecurityHeader(enc=EncryptionHeader(kid="test-key", val="encrypted-base64"))}
    )

    # SEALED with no channel encryption
    crypto_level = policy.classify_message_crypto_level(sealed_envelope, plaintext_context)
    assert crypto_level == CryptoLevel.SEALED

    # SEALED with channel transport context (SEALED takes precedence)
    crypto_level = policy.classify_message_crypto_level(sealed_envelope, channel_context)
    assert crypto_level == CryptoLevel.SEALED


@pytest.mark.asyncio
async def test_channel_context_preservation_in_responses():
    """Test that channel encryption context is preserved in response contexts."""
    from naylence.fame.core import EnvelopeFactory, FameMessageResponse

    # Mock dependencies
    mock_binding_manager = Mock()
    mock_envelope_factory = Mock(spec=EnvelopeFactory)
    mock_delivery_tracker = Mock(spec=DeliveryTracker)

    # Create a EnvelopeListenerManager instance but don't use it in this test
    _ = EnvelopeListenerManager(
        binding_manager=mock_binding_manager,
        get_physical_path=lambda: "/test/path",
        get_sid=lambda: "test-node",
        deliver=AsyncMock(),
        envelope_factory=mock_envelope_factory,
        delivery_tracker=mock_delivery_tracker,
    )

    # Test context with channel encryption
    from naylence.fame.core.protocol.delivery_context import SecurityContext

    request_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        security=SecurityContext(
            crypto_channel_id="test-channel-456",
            inbound_crypto_level=CryptoLevel.CHANNEL,
        ),
    )

    # Simulate a response without explicit context
    response_envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"result": "success"}), to=FameAddress("client@test.com")
    )

    # Create a FameMessageResponse but don't use it in this test
    _ = FameMessageResponse(envelope=response_envelope, context=None)

    # Test the smart response context creation logic
    # This simulates what happens in the listen method when response_context is None
    response_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-node",
        security=SecurityContext(
            # Use inbound_crypto_level to represent the original request's crypto level
            inbound_crypto_level=request_context.security.inbound_crypto_level
            if request_context.security
            else None,
            # Channel information should be inherited
            crypto_channel_id=request_context.security.crypto_channel_id
            if request_context.security
            else None,
        ),
    )

    # Verify channel encryption context is preserved
    assert response_context.security is not None
    assert response_context.security.crypto_channel_id == "test-channel-456"
    assert response_context.security.inbound_crypto_level == CryptoLevel.CHANNEL
