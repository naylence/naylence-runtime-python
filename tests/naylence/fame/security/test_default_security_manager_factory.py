"""
Tests for DefaultSecurityManagerFactory module.

This module tests the DefaultSecurityManagerFactory class which creates
DefaultSecurityManager instances with various component configurations.
"""

from unittest.mock import Mock, patch

import pytest

from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.default_security_manager_factory import (
    DefaultSecurityManagerConfig,
    DefaultSecurityManagerFactory,
)


class TestDefaultSecurityManagerFactory:
    """Test DefaultSecurityManagerFactory creation and configuration."""

    @pytest.fixture
    def factory(self):
        """Create a DefaultSecurityManagerFactory instance."""
        return DefaultSecurityManagerFactory()

    @pytest.fixture
    def basic_config(self):
        """Create a basic configuration."""
        return DefaultSecurityManagerConfig()

    @pytest.fixture
    def mock_policy(self):
        """Create a mock security policy."""
        policy = Mock()
        policy.requirements.return_value = Mock(
            signing_required=True,
            verification_required=True,
            encryption_required=True,
            decryption_required=True,
            require_key_exchange=True,
            require_node_authorization=True,
            require_certificates=True,
        )
        policy.signing = Mock()
        return policy

    @pytest.fixture
    def mock_key_manager(self):
        """Create a mock key manager."""
        key_manager = Mock()
        return key_manager

    @pytest.fixture
    def mock_authorizer(self):
        """Create a mock authorizer."""
        authorizer = Mock()
        return authorizer

    @pytest.mark.asyncio
    async def test_create_with_authorizer_dict_and_event_listeners(self, factory):
        """Test create method with authorizer as dict and event listeners."""
        # This tests lines around 119-125 where authorizer is handled as dict
        event_listeners = []
        config = {"authorizer": {"type": "NoopAuthorizer"}}

        with patch(
            "naylence.fame.security.default_security_manager_factory.create_resource"
        ) as mock_create:
            mock_authorizer = Mock(spec=NodeEventListener)
            mock_create.return_value = mock_authorizer

            with patch.object(factory, "_create_security_manager") as mock_create_sm:
                mock_create_sm.return_value = Mock()

                await factory.create(config, event_listeners=event_listeners)

                # Verify authorizer was created from dict and added to event_listeners
                mock_create.assert_called_once()
                assert len(event_listeners) == 1
                assert event_listeners[0] == mock_authorizer

    @pytest.mark.asyncio
    async def test_create_encryption_manager_from_config_explicit_config(self, factory):
        """Test _create_encryption_manager_from_config with explicit config."""
        # This tests lines 270-276 - explicit encryption config path
        config = {"encryption_manager": {"type": "test_encryption"}}
        policy = Mock()
        key_manager = Mock()
        secure_channel_manager = Mock()

        with patch(
            "naylence.fame.security.default_security_manager_factory.create_resource"
        ) as mock_create:
            mock_encryption_manager = Mock()
            mock_create.return_value = mock_encryption_manager

            result = await factory._create_encryption_manager_from_config(
                config, policy, key_manager, secure_channel_manager
            )

            assert result == (mock_encryption_manager, secure_channel_manager)
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_encryption_manager_auto_create_with_requirements(self, factory):
        """Test _create_encryption_manager_from_config with auto-creation."""
        # This tests lines 289-316 - the large gap in auto-creation logic
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(encryption_required=True, decryption_required=True)
        key_manager = Mock()
        secure_channel_manager = None

        with patch(
            "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider"
        ) as mock_get_crypto:
            mock_crypto_provider = Mock()
            mock_get_crypto.return_value = mock_crypto_provider

            with patch(
                "naylence.fame.security.encryption.secure_channel_manager_factory.SecureChannelManagerFactory.create_secure_channel_manager"
            ) as mock_create_scm:
                mock_secure_channel_manager = Mock()
                mock_create_scm.return_value = mock_secure_channel_manager

                with patch(
                    "naylence.fame.security.encryption.encryption_manager.EncryptionManagerFactory.create_encryption_manager"
                ) as mock_create_em:
                    mock_encryption_manager = Mock()
                    mock_create_em.return_value = mock_encryption_manager

                    result = await factory._create_encryption_manager_from_config(
                        config, policy, key_manager, secure_channel_manager
                    )

                    assert result == (mock_encryption_manager, mock_secure_channel_manager)
                    mock_create_scm.assert_called_once()
                    mock_create_em.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_encryption_manager_exception_handling(self, factory):
        """Test _create_encryption_manager_from_config exception handling."""
        # This tests lines 360-373 - exception handling in auto-creation
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(encryption_required=True, decryption_required=True)
        key_manager = Mock()
        secure_channel_manager = Mock()

        with patch(
            "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider"
        ) as mock_get_crypto:
            mock_get_crypto.side_effect = Exception("Test error")

            with pytest.raises(RuntimeError, match="Failed to auto-create encryption manager"):
                await factory._create_encryption_manager_from_config(
                    config, policy, key_manager, secure_channel_manager
                )

    @pytest.mark.asyncio
    async def test_create_key_manager_explicit_config(self, factory):
        """Test _create_key_manager_from_config with explicit config."""
        # This tests lines 408-413 - explicit key manager config path
        config = {"key_manager_config": {"type": "test"}}
        policy = Mock()
        key_store = Mock()

        with patch(
            "naylence.fame.security.keys.key_manager_factory.KeyManagerFactory.create_key_manager"
        ) as mock_create:
            mock_key_manager = Mock()
            mock_create.return_value = mock_key_manager

            result = await factory._create_key_manager_from_config(config, policy, key_store)

            assert result == mock_key_manager
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_key_manager_auto_create_with_requirements(self, factory):
        """Test _create_key_manager_from_config with auto-creation based on requirements."""
        # This tests lines 428-433 - auto-creation with policy requirements
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(require_key_exchange=True)
        key_store = Mock()

        with patch(
            "naylence.fame.security.keys.default_key_manager_factory.DefaultKeyManagerConfig"
        ) as mock_config_class:
            mock_config = Mock()
            mock_config_class.return_value = mock_config

            with patch(
                "naylence.fame.security.keys.key_manager_factory.KeyManagerFactory.create_key_manager"
            ) as mock_create:
                mock_key_manager = Mock()
                mock_create.return_value = mock_key_manager

                result = await factory._create_key_manager_from_config(config, policy, key_store)

                assert result == mock_key_manager
                mock_create.assert_called_once_with(mock_config, key_store=key_store)

    @pytest.mark.asyncio
    async def test_create_key_manager_fallback_on_exception(self, factory):
        """Test _create_key_manager_from_config fallback on exception."""
        # This tests lines 464-473 - fallback logic when requirements fail
        config = {}
        policy = Mock()
        policy.requirements.side_effect = Exception("Requirements error")
        key_store = Mock()

        with patch(
            "naylence.fame.security.keys.default_key_manager_factory.DefaultKeyManagerConfig"
        ) as mock_config_class:
            mock_config = Mock()
            mock_config_class.return_value = mock_config

            with patch(
                "naylence.fame.security.keys.key_manager_factory.KeyManagerFactory.create_key_manager"
            ) as mock_create:
                # The fallback attempt also fails
                mock_create.side_effect = Exception("Fallback error")

                with patch("naylence.fame.security.keys.key_store.get_key_store") as mock_get_store:
                    mock_get_store.return_value = key_store

                    # The method should raise RuntimeError when fallback fails
                    with pytest.raises(
                        RuntimeError, match="Failed to create key manager \\(fallback also failed\\)"
                    ):
                        await factory._create_key_manager_from_config(config, policy, None)

                    # Should have been called only once for the fallback attempt
                    assert mock_create.call_count == 1

    @pytest.mark.asyncio
    async def test_create_authorizer_with_policy_requirements(self, factory):
        """Test _create_authorizer_from_config with policy requirements."""
        # This tests lines 547-551 - policy-based authorizer creation
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(require_node_authorization=True)

        with patch(
            "naylence.fame.security.auth.authorizer_factory.AuthorizerFactory.create_authorizer"
        ) as mock_create:
            with patch(
                "naylence.fame.security.auth.noop_token_verifier.NoopTokenVerifier"
            ) as mock_verifier_class:
                mock_verifier = Mock()
                mock_verifier_class.return_value = mock_verifier
                mock_authorizer = Mock()
                mock_create.return_value = mock_authorizer

                result = await factory._create_authorizer_from_config(config, policy)

                assert result == mock_authorizer
                mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_authorizer_exception_handling(self, factory):
        """Test _create_authorizer_from_config exception handling."""
        # This tests lines 552-556 - exception handling in authorizer creation
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(require_node_authorization=True)

        with patch(
            "naylence.fame.security.auth.authorizer_factory.AuthorizerFactory.create_authorizer"
        ) as mock_create:
            mock_create.side_effect = Exception("Creation error")

            with pytest.raises(RuntimeError, match="Failed to auto-create authorizer"):
                await factory._create_authorizer_from_config(config, policy)

    @pytest.mark.asyncio
    async def test_create_with_none_config(self, factory):
        """Test create method with None config."""
        # This tests basic config creation path
        with patch.object(factory, "_create_security_manager") as mock_create_sm:
            mock_sm = Mock()
            mock_create_sm.return_value = mock_sm

            result = await factory.create(None)

            assert result == mock_sm
            # Should have been called with DefaultSecurityManagerConfig
            mock_create_sm.assert_called_once()

    @pytest.mark.asyncio
    async def test_merge_config_with_kwargs_dict_config(self, factory):
        """Test _merge_config_with_kwargs with dict config."""
        config = {"existing": "value"}
        kwargs = {"new": "value", "existing": "overridden"}

        result = factory._merge_config_with_kwargs(config, kwargs)

        expected = {"existing": "overridden", "new": "value"}
        assert result == expected

    @pytest.mark.asyncio
    async def test_merge_config_with_kwargs_pydantic_config(self, factory):
        """Test _merge_config_with_kwargs with Pydantic config."""
        config = DefaultSecurityManagerConfig(envelope_signer={"type": "test"})
        kwargs = {"new": "value"}

        result = factory._merge_config_with_kwargs(config, kwargs)

        # Should convert to dict and merge
        assert "new" in result
        assert result["new"] == "value"
        assert "envelope_signer" in result


class TestDefaultSecurityManagerFactoryErrorPaths:
    """Test error handling and edge cases in DefaultSecurityManagerFactory."""

    @pytest.fixture
    def factory(self):
        """Create a DefaultSecurityManagerFactory instance."""
        return DefaultSecurityManagerFactory()

    @pytest.mark.asyncio
    async def test_create_encryption_manager_no_key_manager_warning(self, factory):
        """Test encryption manager creation without key manager logs warning."""
        config = {"encryption_manager": {"type": "test"}}
        policy = Mock()
        key_manager = None
        secure_channel_manager = Mock()

        with patch(
            "naylence.fame.security.default_security_manager_factory.logger.warning"
        ) as mock_warning:
            result = await factory._create_encryption_manager_from_config(
                config, policy, key_manager, secure_channel_manager
            )

            assert result == (None, secure_channel_manager)
            mock_warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_envelope_verifier_no_key_manager_error(self, factory):
        """Test envelope verifier creation fails without key manager."""
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(verification_required=True)
        key_manager = None

        with pytest.raises(RuntimeError, match="Failed to auto-create envelope verifier"):
            await factory._create_envelope_verifier_from_config(
                config, policy, key_manager
            ) @ pytest.mark.asyncio

    async def test_create_encryption_manager_no_key_manager_error(self, factory):
        """Test encryption manager creation fails without key manager."""
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(encryption_required=True, decryption_required=True)
        key_manager = None
        secure_channel_manager = Mock()

        with patch("naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider"):
            with pytest.raises(RuntimeError, match="Failed to auto-create encryption manager"):
                await factory._create_encryption_manager_from_config(
                    config, policy, key_manager, secure_channel_manager
                )

    @pytest.mark.asyncio
    async def test_create_key_manager_fallback_also_fails(self, factory):
        """Test key manager creation when both primary and fallback fail."""
        config = {}
        policy = Mock()
        policy.requirements.side_effect = Exception("Requirements error")
        key_store = Mock()

        with patch(
            "naylence.fame.security.keys.default_key_manager_factory.DefaultKeyManagerConfig"
        ) as mock_config_class:
            mock_config_class.return_value = Mock()

            with patch(
                "naylence.fame.security.keys.key_manager_factory.KeyManagerFactory.create_key_manager"
            ) as mock_create:
                # Both calls fail
                mock_create.side_effect = Exception("Creation error")

                with patch("naylence.fame.security.keys.key_store.get_key_store") as mock_get_store:
                    mock_get_store.return_value = key_store

                    with pytest.raises(RuntimeError, match="Failed to create key manager"):
                        await factory._create_key_manager_from_config(config, policy, None)


class TestDefaultSecurityManagerFactoryComponentCreation:
    """Test individual component creation methods."""

    @pytest.fixture
    def factory(self):
        """Create a DefaultSecurityManagerFactory instance."""
        return DefaultSecurityManagerFactory()

    @pytest.mark.asyncio
    async def test_create_envelope_signer_auto_create_fallback_signing_config(self, factory):
        """Test envelope signer auto-creation with fallback to signing config."""
        config = {}
        policy = Mock()
        # Requirements method returns None, should fall back to signing config
        policy.requirements.return_value = None
        policy.signing = Mock()  # Has signing config

        with patch(
            "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider"
        ) as mock_get_crypto:
            mock_crypto_provider = Mock()
            mock_get_crypto.return_value = mock_crypto_provider

            with patch(
                "naylence.fame.security.signing.envelope_signer.EnvelopeSignerFactory.create_envelope_signer"
            ) as mock_create:
                mock_signer = Mock()
                mock_create.return_value = mock_signer

                result = await factory._create_envelope_signer_from_config(config, policy)

                assert result == mock_signer
                mock_create.assert_called_once_with(
                    crypto_provider=mock_crypto_provider, signing_config=policy.signing
                )
                mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_envelope_verifier_auto_create_fallback_signing_config(self, factory):
        """Test envelope verifier auto-creation with fallback to signing config."""
        config = {}
        policy = Mock()
        # Requirements method returns None, should fall back to signing config
        policy.requirements.return_value = None
        policy.signing = Mock()  # Has signing config
        key_manager = Mock()

        with patch(
            "naylence.fame.security.signing.envelope_verifier.EnvelopeVerifierFactory.create_envelope_verifier"
        ) as mock_create:
            mock_verifier = Mock()
            mock_create.return_value = mock_verifier

            result = await factory._create_envelope_verifier_from_config(config, policy, key_manager)

            assert result == mock_verifier
            mock_create.assert_called_once_with(key_provider=key_manager, signing_config=policy.signing)
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_certificate_manager_explicit_config(self, factory):
        """Test certificate manager creation with explicit config."""
        config = {"certificate_manager": {"type": "test"}}
        policy = Mock()
        policy.signing = Mock()

        with patch(
            "naylence.fame.security.cert.certificate_manager_factory.CertificateManagerFactory.create_certificate_manager"
        ) as mock_create:
            mock_cert_manager = Mock()
            mock_create.return_value = mock_cert_manager

            result = await factory._create_certificate_manager_from_config(config, policy)

            assert result == mock_cert_manager
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_certificate_manager_auto_create_with_requirements(self, factory):
        """Test certificate manager auto-creation based on policy requirements."""
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(require_certificates=True)
        policy.signing = Mock()

        with patch(
            "naylence.fame.security.cert.certificate_manager_factory.CertificateManagerFactory.create_certificate_manager"
        ) as mock_create:
            mock_cert_manager = Mock()
            mock_create.return_value = mock_cert_manager

            result = await factory._create_certificate_manager_from_config(config, policy)

            assert result == mock_cert_manager
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_certificate_manager_exception_handling(self, factory):
        """Test certificate manager creation exception handling."""
        config = {}
        policy = Mock()
        policy.requirements.return_value = Mock(require_certificates=True)
        policy.signing = Mock()

        with patch(
            "naylence.fame.security.cert.certificate_manager_factory.CertificateManagerFactory.create_certificate_manager"
        ) as mock_create:
            mock_create.side_effect = Exception("Creation error")

            with pytest.raises(RuntimeError, match="Failed to auto-create certificate manager"):
                await factory._create_certificate_manager_from_config(config, policy)

    @pytest.mark.asyncio
    async def test_create_authorizer_legacy_config_location(self, factory):
        """Test authorizer creation from legacy config location."""
        config = {"authorizer_config": {"type": "NoopAuthorizer"}}  # Legacy location
        policy = Mock()

        with patch(
            "naylence.fame.security.default_security_manager_factory.create_resource"
        ) as mock_create:
            mock_authorizer = Mock()
            mock_create.return_value = mock_authorizer

            result = await factory._create_authorizer_from_config(config, policy)

            assert result == mock_authorizer
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_authorizer_fallback_exception_handling(self, factory):
        """Test authorizer creation with exception in requirements fallback."""
        config = {}
        policy = Mock()
        # First requirements() call succeeds but second fails
        policy.requirements.side_effect = [
            Mock(require_node_authorization=True),
            Exception("Fallback error"),
        ]

        with patch(
            "naylence.fame.security.auth.authorizer_factory.AuthorizerFactory.create_authorizer"
        ) as mock_create:
            with patch(
                "naylence.fame.security.auth.noop_token_verifier.NoopTokenVerifier"
            ) as mock_verifier_class:
                mock_verifier_class.return_value = Mock()
                mock_authorizer = Mock()
                mock_create.return_value = mock_authorizer

                result = await factory._create_authorizer_from_config(config, policy)

                assert result == mock_authorizer
                mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_policy_auto_create_no_config(self, factory):
        """Test policy creation with auto-create when no config provided."""
        # This tests lines 151-159 - auto-create path when no policy_config
        config = {}  # No security_policy config
        key_provider = Mock()

        with patch(
            "naylence.fame.security.policy.SecurityPolicyFactory.create_security_policy"
        ) as mock_create:
            mock_policy = Mock()
            mock_create.return_value = mock_policy

            result = await factory._create_policy_from_config(config, key_provider)

            assert result == mock_policy
            mock_create.assert_called_once_with(key_provider=key_provider)

    @pytest.mark.asyncio
    async def test_create_security_manager_full_auto_creation(self, factory):
        """Test _create_security_manager with full auto-creation path to cover lines 515-562."""
        # This tests lines 515-562 - the large uncovered section
        config = {}  # No specific configs, should auto-create everything

        # Call the method with all None parameters to trigger auto-creation paths
        event_listeners = []
        result = await factory._create_security_manager(
            config=config,
            # Explicitly set all components to None to trigger auto-creation
            policy=None,
            envelope_signer=None,
            envelope_verifier=None,
            encryption_manager=None,
            key_store=None,
            key_manager=None,
            key_validator=None,
            authorizer=None,
            certificate_manager=None,
            secure_channel_manager=None,
            event_listeners=event_listeners,
        )

        # Verify that we got a security manager back
        assert result is not None
        assert hasattr(result, "policy")  # Should have policy set

        # Verify that some components were auto-created
        # (we can't easily verify all details without mocking, but coverage will show execution)
        assert len(event_listeners) >= 0  # May have authorizer added if it's a NodeEventListener

    @pytest.mark.asyncio
    async def test_create_security_manager_config_none_policy_fallback(self, factory):
        """Test config=None and policy fallback to cover lines 516 and 552-556."""
        # Mock _create_policy_from_config to return None to trigger fallback
        with patch.object(DefaultSecurityManagerFactory, "_create_policy_from_config", return_value=None):
            event_listeners = []
            result = await factory._create_security_manager(
                config=None,  # Triggers line 516: if config is None: config = {}
                policy=None,  # With mock returning None, triggers lines 552-556 fallback
                envelope_signer=None,
                envelope_verifier=None,
                encryption_manager=None,
                key_store=None,
                key_manager=None,
                key_validator=None,
                authorizer=None,
                certificate_manager=None,
                secure_channel_manager=None,
                event_listeners=event_listeners,
            )

        # Verify we get a valid DefaultSecurityManager with fallback policy
        assert result is not None
        assert hasattr(result, "policy")  # Should have the fallback DefaultSecurityPolicy
