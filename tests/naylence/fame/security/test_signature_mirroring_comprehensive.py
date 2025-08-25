#!/usr/bin/env python3
"""
Comprehensive test for signature mirroring functionality.

This test verifies that the signature mirroring logic correctly handles all scenarios:
1. Signed but unencrypted requests (should trigger mirroring)
2. Unsigned plaintext requests (should not trigger mirroring)
3. Signed and encrypted requests (should trigger mirroring)
4. Disabled mirroring (should not trigger mirroring regardless)
"""

import pytest

from naylence.fame.core import DataFrame, DeliveryOriginType, FameDeliveryContext, FameEnvelope, generate_id
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    ResponseCryptoRules,
    ResponseSigningRules,
    SigningConfig,
)


@pytest.mark.asyncio
async def test_signature_mirroring_signed_unencrypted_request():
    """Test that signed but unencrypted requests trigger signature mirroring."""
    print("🧪 Testing signature mirroring with signed but unencrypted request...")

    # Create security policy with mirror_request_signing enabled and plaintext responses allowed
    signing_config = SigningConfig(
        response=ResponseSigningRules(
            mirror_request_signing=True, always_sign_responses=False, sign_error_responses=False
        )
    )

    # Allow plaintext responses to properly test signature mirroring without encryption interference
    encryption_config = EncryptionConfig(
        response=ResponseCryptoRules(
            mirror_request_level=True,
            minimum_response_level=CryptoLevel.PLAINTEXT,  # Allow plaintext responses
        )
    )

    policy = DefaultSecurityPolicy(signing=signing_config, encryption=encryption_config)

    # Create a response envelope
    envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"response": "test data"}, codec="json")
    )

    # Create context with PLAINTEXT crypto level and signed
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-system",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.PLAINTEXT,
            inbound_was_signed=True,  # Original request was signed
        ),
        meta={"message-type": "response"},
    )

    # Test signature decision
    should_encrypt = await policy.should_encrypt_envelope(envelope, context)
    should_sign = await policy.should_sign_envelope(envelope, context)

    print(f"   Context security: {context.security}")
    print(f"   Inbound crypto level: {context.security.inbound_crypto_level if context.security else None}")
    print(f"   Inbound was signed: {context.security.inbound_was_signed if context.security else None}")
    print(f"   Should encrypt result: {should_encrypt}")
    print(f"   Should sign result: {should_sign}")

    # Should NOT encrypt (plaintext crypto level)
    assert not should_encrypt, "Should not encrypt response to plaintext request"

    # Should sign because original request was signed (signature mirroring)
    assert should_sign, "Should sign response to signed request when mirroring is enabled"

    print("✅ Signed but unencrypted request triggers signature mirroring")


@pytest.mark.asyncio
async def test_signature_mirroring_unsigned_plaintext_request():
    """Test that unsigned plaintext requests do not trigger signature mirroring."""
    print("🧪 Testing signature mirroring with unsigned plaintext request...")

    # Create security policy with mirror_request_signing enabled and plaintext responses allowed
    signing_config = SigningConfig(
        response=ResponseSigningRules(
            mirror_request_signing=True, always_sign_responses=False, sign_error_responses=False
        )
    )

    # Allow plaintext responses to properly test signature mirroring without encryption interference
    encryption_config = EncryptionConfig(
        response=ResponseCryptoRules(
            mirror_request_level=True,
            minimum_response_level=CryptoLevel.PLAINTEXT,  # Allow plaintext responses
        )
    )

    policy = DefaultSecurityPolicy(signing=signing_config, encryption=encryption_config)

    # Create a response envelope
    envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"response": "test data"}, codec="json")
    )

    # Create context with PLAINTEXT crypto level and not signed
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-system",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.PLAINTEXT,
            inbound_was_signed=False,  # Original request was not signed
        ),
        meta={"message-type": "response"},
    )

    # Test signature decision
    should_encrypt = await policy.should_encrypt_envelope(envelope, context)
    should_sign = await policy.should_sign_envelope(envelope, context)

    print(f"   Context security: {context.security}")
    print(f"   Inbound crypto level: {context.security.inbound_crypto_level if context.security else None}")
    print(f"   Inbound was signed: {context.security.inbound_was_signed if context.security else None}")
    print(f"   Should encrypt result: {should_encrypt}")
    print(f"   Should sign result: {should_sign}")

    # Should NOT encrypt (plaintext crypto level)
    assert not should_encrypt, "Should not encrypt response to plaintext request"

    # Should NOT sign because original request was not signed
    assert not should_sign, "Should not sign response to unsigned request when mirroring is enabled"

    print("✅ Unsigned plaintext request does not trigger signature mirroring")


async def test_signature_mirroring_signed_encrypted_request():
    """Test that signed and encrypted requests trigger signature mirroring."""
    print("🧪 Testing signature mirroring with signed and encrypted request...")

    # Create security policy with mirror_request_signing enabled
    signing_config = SigningConfig(
        response=ResponseSigningRules(
            mirror_request_signing=True, always_sign_responses=False, sign_error_responses=False
        )
    )

    policy = DefaultSecurityPolicy(signing=signing_config)

    # Create a response envelope
    envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"response": "test data"}, codec="json")
    )

    # Create context with SEALED crypto level and signed
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-system",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.SEALED,
            inbound_was_signed=True,  # Original request was signed and encrypted
        ),
        meta={"message-type": "response"},
    )

    # Test signature decision
    should_sign = await policy.should_sign_envelope(envelope, context)

    print(f"   Context security: {context.security}")
    print(f"   Inbound crypto level: {context.security.inbound_crypto_level if context.security else None}")
    print(f"   Inbound was signed: {context.security.inbound_was_signed if context.security else None}")
    print(f"   Should sign result: {should_sign}")

    # Should sign because original request was signed (signature mirroring)
    assert should_sign, "Should sign response to signed request when mirroring is enabled"

    print("✅ Signed and encrypted request triggers signature mirroring")


@pytest.mark.asyncio
async def test_signature_mirroring_fallback_logic():
    """Test the fallback logic when inbound_was_signed is not available."""
    print("🧪 Testing signature mirroring fallback logic...")

    # Create security policy with mirror_request_signing enabled
    signing_config = SigningConfig(
        response=ResponseSigningRules(
            mirror_request_signing=True, always_sign_responses=False, sign_error_responses=False
        )
    )

    policy = DefaultSecurityPolicy(signing=signing_config)

    # Create a response envelope
    envelope = FameEnvelope(
        cid=generate_id(), frame=DataFrame(payload={"response": "test data"}, codec="json")
    )

    # Create context with only crypto level (no inbound_was_signed field)
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-system",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.SEALED
            # No inbound_was_signed field - fallback logic should be used
        ),
        meta={"message-type": "response"},
    )

    # Test signature decision
    should_sign = await policy.should_sign_envelope(envelope, context)

    print(f"   Context security: {context.security}")
    print(f"   Inbound crypto level: {context.security.inbound_crypto_level if context.security else None}")
    print(f"   Inbound was signed: {context.security.inbound_was_signed if context.security else None}")
    print(f"   Should sign result: {should_sign}")

    # Should sign because fallback logic sees encrypted request (signature mirroring)
    assert should_sign, "Should sign response using fallback logic for encrypted request"

    print("✅ Fallback logic works for encrypted requests without explicit signature tracking")


@pytest.mark.asyncio
async def test_signature_mirroring_disabled_with_signed_request():
    """Test that signature mirroring can be disabled even for signed requests."""
    print("🧪 Testing disabled signature mirroring with signed request...")

    # Create security policy with mirror_request_signing disabled
    signing_config = SigningConfig(
        response=ResponseSigningRules(
            mirror_request_signing=False,  # Disabled
            always_sign_responses=False,
            sign_error_responses=False,
        )
    )

    policy = DefaultSecurityPolicy(signing=signing_config)

    # Create a response envelope
    envelope = FameEnvelope(
        cid=generate_id(), frame=DataFrame(payload={"response": "test data"}, codec="json")
    )

    # Create context with signed request
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-system",
        security=SecurityContext(
            inbound_crypto_level=CryptoLevel.PLAINTEXT,
            inbound_was_signed=True,  # Original request was signed
        ),
        meta={"message-type": "response"},
    )

    # Test signature decision
    should_sign = await policy.should_sign_envelope(envelope, context)

    print(f"   Context security: {context.security}")
    print(f"   Inbound crypto level: {context.security.inbound_crypto_level if context.security else None}")
    print(f"   Inbound was signed: {context.security.inbound_was_signed if context.security else None}")
    print(f"   Should sign result: {should_sign}")

    # Should NOT sign because mirroring is disabled
    assert not should_sign, "Should not sign when mirroring is disabled, even for signed requests"

    print("✅ Signature mirroring can be disabled")
