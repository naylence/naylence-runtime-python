"""
Test the SecurityPolicy factory framework.
"""

import pytest

from naylence.fame.security.policy.default_security_policy_factory import (
    DefaultSecurityPolicyConfig,
    DefaultSecurityPolicyFactory,
)
from naylence.fame.security.policy.no_security_policy_factory import (
    NoSecurityPolicyConfig,
    NoSecurityPolicyFactory,
)
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    InboundCryptoRules,
    InboundSigningRules,
    OutboundCryptoRules,
    OutboundSigningRules,
    ResponseCryptoRules,
    ResponseSigningRules,
    SignaturePolicy,
    SigningConfig,
)


@pytest.mark.asyncio
async def test_default_security_policy_factory():
    """Test DefaultSecurityPolicyFactory."""
    factory = DefaultSecurityPolicyFactory()

    # Test with default config
    config = DefaultSecurityPolicyConfig()
    policy = await factory.create(config)

    assert policy is not None
    assert hasattr(policy, "should_sign_envelope")
    assert hasattr(policy, "should_encrypt_envelope")
    assert hasattr(policy, "get_encryption_options")
    assert hasattr(policy, "should_verify_signature")
    assert hasattr(policy, "should_decrypt_envelope")

    # Test with custom flexible crypto config
    encryption_config = EncryptionConfig(
        outbound=OutboundCryptoRules(default_level=CryptoLevel.SEALED),
        response=ResponseCryptoRules(minimum_response_level=CryptoLevel.SEALED),
        inbound=InboundCryptoRules(allow_plaintext=False),
    )
    signing_config = SigningConfig(
        outbound=OutboundSigningRules(default_signing=True),
        response=ResponseSigningRules(always_sign_responses=True),
        inbound=InboundSigningRules(signature_policy=SignaturePolicy.REQUIRED),
    )
    custom_config = DefaultSecurityPolicyConfig(encryption=encryption_config, signing=signing_config)
    custom_policy = await factory.create(custom_config)

    # Verify the policy uses the flexible configs
    assert custom_policy.encryption is not None
    assert custom_policy.encryption.outbound.default_level == CryptoLevel.SEALED
    assert custom_policy.encryption.response.minimum_response_level == CryptoLevel.SEALED
    assert custom_policy.encryption.inbound.allow_plaintext is False

    assert custom_policy.signing is not None
    assert custom_policy.signing.outbound.default_signing is True
    assert custom_policy.signing.response.always_sign_responses is True
    assert custom_policy.signing.inbound.signature_policy == SignaturePolicy.REQUIRED


@pytest.mark.asyncio
async def test_no_security_policy_factory():
    """Test NoSecurityPolicyFactory."""
    factory = NoSecurityPolicyFactory()
    config = NoSecurityPolicyConfig()

    policy = await factory.create(config)

    assert policy is not None

    # NoSecurityPolicy should disable all security operations
    from unittest.mock import Mock

    envelope = Mock()
    assert await policy.should_sign_envelope(envelope) is False
    assert await policy.should_encrypt_envelope(envelope) is False
    assert await policy.should_verify_signature(envelope) is False
    assert await policy.get_encryption_options(envelope) is None


@pytest.mark.asyncio
async def test_factory_with_kwargs():
    """Test that factories accept runtime kwargs."""
    factory = DefaultSecurityPolicyFactory()

    # Override config with flexible crypto config kwargs
    encryption_config = EncryptionConfig(
        outbound=OutboundCryptoRules(default_level=CryptoLevel.SEALED),
        inbound=InboundCryptoRules(allow_plaintext=False),
    )
    signing_config = SigningConfig(
        outbound=OutboundSigningRules(default_signing=False),
        inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
    )

    policy = await factory.create(
        config=None,
        encryption=encryption_config,
        signing=signing_config,
    )

    assert policy.encryption is not None
    assert policy.encryption.outbound.default_level == CryptoLevel.SEALED
    assert policy.encryption.inbound.allow_plaintext is False
    assert policy.signing is not None
    assert policy.signing.outbound.default_signing is False
    assert policy.signing.inbound.signature_policy == SignaturePolicy.OPTIONAL
