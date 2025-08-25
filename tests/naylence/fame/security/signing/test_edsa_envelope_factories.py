"""Tests for EdDSA envelope signer and verifier factories."""

from unittest.mock import Mock

import pytest

from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
from naylence.fame.security.signing.eddsa_envelope_signer_factory import (
    EdDSAEnvelopeSignerConfig,
    EdDSAEnvelopeSignerFactory,
)
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier
from naylence.fame.security.signing.eddsa_envelope_verifier_factory import (
    EdDSAEnvelopeVerifierConfig,
    EdDSAEnvelopeVerifierFactory,
)


@pytest.mark.asyncio
class TestEdDSAEnvelopeSignerFactory:
    """Test the EdDSA envelope signer factory."""

    async def test_create_signer_with_crypto_provider(self):
        """Test creating signer with crypto provider."""
        factory = EdDSAEnvelopeSignerFactory()
        mock_crypto = Mock()
        config = EdDSAEnvelopeSignerConfig(type="EdDSAEnvelopeSigner")

        signer = await factory.create(config, crypto_provider=mock_crypto)

        assert isinstance(signer, EdDSAEnvelopeSigner)
        assert signer._crypto == mock_crypto

    async def test_create_signer_without_config(self):
        """Test creating signer without config parameter."""
        factory = EdDSAEnvelopeSignerFactory()
        mock_crypto = Mock()

        signer = await factory.create(crypto_provider=mock_crypto)

        assert isinstance(signer, EdDSAEnvelopeSigner)
        assert signer._crypto == mock_crypto

    async def test_create_signer_with_none_config(self):
        """Test creating signer with None config."""
        factory = EdDSAEnvelopeSignerFactory()
        mock_crypto = Mock()

        signer = await factory.create(None, crypto_provider=mock_crypto)

        assert isinstance(signer, EdDSAEnvelopeSigner)
        assert signer._crypto == mock_crypto

    async def test_create_signer_without_crypto_parameter(self):
        """Test creating signer without crypto parameter."""
        factory = EdDSAEnvelopeSignerFactory()
        config = EdDSAEnvelopeSignerConfig(type="EdDSAEnvelopeSigner")

        signer = await factory.create(config)

        assert isinstance(signer, EdDSAEnvelopeSigner)
        assert signer._crypto is not None  # Default crypto provider

    async def test_create_signer_with_extra_kwargs(self):
        """Test creating signer with extra keyword arguments."""
        factory = EdDSAEnvelopeSignerFactory()
        mock_crypto = Mock()
        config = EdDSAEnvelopeSignerConfig(type="EdDSAEnvelopeSigner")

        signer = await factory.create(
            config, crypto_provider=mock_crypto, extra_param="ignored", another_param=123
        )

        assert isinstance(signer, EdDSAEnvelopeSigner)
        assert signer._crypto == mock_crypto


@pytest.mark.asyncio
class TestEdDSAEnvelopeVerifierFactory:
    """Test the EdDSA envelope verifier factory."""

    async def test_create_verifier_with_config(self):
        """Test creating verifier with valid config."""
        from naylence.fame.security.keys.key_provider import get_key_provider

        factory = EdDSAEnvelopeVerifierFactory()
        config = EdDSAEnvelopeVerifierConfig(type="EdDSAEnvelopeVerifier")

        verifier = await factory.create(config, key_provider=get_key_provider())

        assert isinstance(verifier, EdDSAEnvelopeVerifier)

    async def test_create_verifier_fails_without_config(self):
        """Test creating verifier fails without config."""
        from naylence.fame.security.keys.key_provider import get_key_provider

        factory = EdDSAEnvelopeVerifierFactory()

        with pytest.raises(AssertionError, match="EdDSAVerifierFactory requires a config"):
            await factory.create(None, key_provider=get_key_provider())

    async def test_create_verifier_fails_with_empty_config(self):
        """Test creating verifier fails with falsy config."""
        from naylence.fame.security.keys.key_provider import get_key_provider

        factory = EdDSAEnvelopeVerifierFactory()

        # Empty config should fail the assertion
        with pytest.raises(AssertionError, match="EdDSAVerifierFactory requires a config"):
            await factory.create(None, key_provider=get_key_provider())

    async def test_create_verifier_ignores_extra_kwargs(self):
        """Test creating verifier ignores extra keyword arguments."""
        from naylence.fame.security.keys.key_provider import get_key_provider

        factory = EdDSAEnvelopeVerifierFactory()
        config = EdDSAEnvelopeVerifierConfig(type="EdDSAEnvelopeVerifier")

        verifier = await factory.create(
            config,
            key_provider=get_key_provider(),
            extra_param="ignored",
            another_param=123,
            crypto="also_ignored",
        )

        assert isinstance(verifier, EdDSAEnvelopeVerifier)


class TestEdDSAEnvelopeSignerConfig:
    """Test the EdDSA envelope signer config."""

    def test_config_inheritance(self):
        """Test that config inherits from base class."""
        from naylence.fame.security.signing.envelope_signer import EnvelopeSignerConfig

        config = EdDSAEnvelopeSignerConfig(type="EdDSAEnvelopeSigner")
        assert isinstance(config, EnvelopeSignerConfig)

    def test_config_instantiation(self):
        """Test config can be instantiated."""
        config = EdDSAEnvelopeSignerConfig(type="EdDSAEnvelopeSigner")
        assert config is not None


class TestEdDSAEnvelopeVerifierConfig:
    """Test the EdDSA envelope verifier config."""

    def test_config_inheritance(self):
        """Test that config inherits from base class."""
        from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifierConfig

        config = EdDSAEnvelopeVerifierConfig(type="EdDSAEnvelopeVerifier")
        assert isinstance(config, EnvelopeVerifierConfig)

    def test_config_instantiation(self):
        """Test config can be instantiated."""
        config = EdDSAEnvelopeVerifierConfig(type="EdDSAEnvelopeVerifier")
        assert config is not None
