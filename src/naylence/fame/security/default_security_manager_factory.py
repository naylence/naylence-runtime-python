"""
Factory for creating DefaultSecurityManager instances.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.encryption.encryption_manager import EncryptionManager
from naylence.fame.security.encryption.secure_channel_manager import (
    SecureChannelManager,
)
from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.security.keys.key_manager_factory import KeyManagerFactory
from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.security.policy import SecurityPolicy
from naylence.fame.security.security_manager_config import SecurityManagerConfig
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier
from naylence.fame.util.logging import getLogger

from .security_manager import SecurityManager
from .security_manager_factory import SecurityManagerFactory

if TYPE_CHECKING:
    from naylence.fame.security.auth.authorizer import Authorizer
    from naylence.fame.security.cert.certificate_manager import CertificateManager
    from naylence.fame.security.keys.key_manager import KeyManager

logger = getLogger(__name__)


class DefaultSecurityManagerConfig(SecurityManagerConfig):
    """Configuration for DefaultSecurityManager."""

    type: str = "DefaultSecurityManager"

    envelope_signer: Optional[dict[str, Any]] = Field(
        default=None,
        description="Envelope signer configuration",
    )

    envelope_verifier: Optional[dict[str, Any]] = Field(
        default=None,
        description="Envelope verifier configuration",
    )

    encryption_manager: Optional[dict[str, Any]] = Field(
        default=None,
        description="Encryption manager configuration",
    )

    security_policy: Optional[dict[str, Any]] = Field(
        default=None,
        description="Security policy configuration",
    )

    authorizer: Optional[dict[str, Any]] = Field(
        default=None,
        description="Authorizer configuration for authentication and authorization",
    )

    certificate_manager: Optional[dict[str, Any]] = Field(
        default=None,
        description="Certificate manager configuration",
    )


class DefaultSecurityManagerFactory(SecurityManagerFactory):
    """Factory for creating DefaultSecurityManager instances."""

    type: str = "DefaultSecurityManager"
    is_default: bool = True  # Mark as default implementation

    async def create(
        self,
        config: Optional[DefaultSecurityManagerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> SecurityManager:
        """Create a DefaultSecurityManager instance."""
        if config is None:
            config = DefaultSecurityManagerConfig()

        # Allow runtime overrides from kwargs
        effective_config = self._merge_config_with_kwargs(config, kwargs)

        # Extract any pre-existing component instances from config or kwargs
        # TODO: effective_config already merged with kwargs, no need to check kwargs below
        provided_components = {
            "policy": effective_config.get("policy") or kwargs.get("policy"),
            "envelope_signer": effective_config.get("envelope_signer") or kwargs.get("envelope_signer"),
            "envelope_verifier": effective_config.get("envelope_verifier")
            or kwargs.get("envelope_verifier"),
            "encryption_manager": (
                effective_config.get("encryption")
                or kwargs.get("encryption")
                or kwargs.get("encryption_manager")
            ),
            "key_store": effective_config.get("key_store") or kwargs.get("key_store"),
            "key_manager": effective_config.get("key_manager") or kwargs.get("key_manager"),
            "authorizer": effective_config.get("authorizer") or kwargs.get("authorizer"),
            "certificate_manager": effective_config.get("certificate_manager")
            or kwargs.get("certificate_manager"),
            "secure_channel_manager": effective_config.get("secure_channel_manager")
            or kwargs.get("secure_channel_manager"),
            "key_validator": effective_config.get("key_validator") or kwargs.get("key_validator"),
            "event_listeners": kwargs.get("event_listeners"),
        }

        # Handle special case: authorizer as config dict needs to be created
        event_listeners: Optional[List[NodeEventListener]] = provided_components.get("event_listeners")
        authorizer = provided_components["authorizer"]
        if isinstance(authorizer, dict):
            from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory

            authorizer = provided_components["authorizer"] = await create_resource(
                AuthorizerFactory, authorizer
            )
            if event_listeners is not None and isinstance(authorizer, NodeEventListener):
                event_listeners.append(authorizer)

        # Delegate all component creation and assembly to _create_security_manager
        return await self._create_security_manager(config=effective_config, **provided_components)

    def _merge_config_with_kwargs(
        self, config: DefaultSecurityManagerConfig | dict[str, Any], kwargs: dict
    ) -> dict:
        """Merge configuration with runtime kwargs, with kwargs taking precedence."""
        if isinstance(config, dict):
            effective_config = dict(config)
        else:
            effective_config = config.model_dump(exclude_none=True)

        # Override with any provided kwargs
        for key, value in kwargs.items():
            if value is not None:
                effective_config[key] = value

        return effective_config

    @classmethod
    async def _create_policy_from_config(
        cls, config: dict, key_provider: Optional[KeyProvider]
    ) -> Optional[SecurityPolicy]:
        """Create security policy from configuration."""
        policy_config = config.get("security_policy")

        from naylence.fame.security.policy import SecurityPolicyFactory

        if policy_config:
            return await create_resource(SecurityPolicyFactory, policy_config, key_provider=key_provider)

        # Auto-create default policy
        return await SecurityPolicyFactory.create_security_policy(key_provider=key_provider)

    @classmethod
    async def _create_envelope_signer_from_config(
        cls, config: dict, policy: Optional[SecurityPolicy]
    ) -> Optional[EnvelopeSigner]:
        """Create envelope signer from configuration or auto-create if needed."""
        signer_config = config.get("envelope_signer")
        from naylence.fame.security.signing.envelope_signer import EnvelopeSignerFactory

        if signer_config:
            # Explicit configuration - re-raise any exceptions
            return await create_resource(EnvelopeSignerFactory, signer_config)

        # Auto-create if policy requires it
        if policy:
            try:
                requirements = policy.requirements()
                should_create_signer = False
                if requirements:
                    # Create signer if signing is required OR if verification is required
                    should_create_signer = (
                        requirements.signing_required or requirements.verification_required
                    )
                else:
                    # Fallback: check signing config
                    signing_config = getattr(policy, "signing", None)
                    should_create_signer = bool(signing_config)

                if should_create_signer:
                    from naylence.fame.security.crypto.providers.crypto_provider import (
                        get_crypto_provider,
                    )

                    crypto_provider = get_crypto_provider()
                    signing_config = getattr(policy, "signing", None)
                    return await EnvelopeSignerFactory.create_envelope_signer(
                        crypto_provider=crypto_provider, signing_config=signing_config
                    )
            except Exception as e:
                # Re-raise auto-creation failures for better debugging
                logger.error("failed_to_auto_create_envelope_signer", exc_info=True)
                raise RuntimeError(f"Failed to auto-create envelope signer: {e}") from e

        return None

    @classmethod
    async def _create_envelope_verifier_from_config(
        cls,
        config: dict,
        policy: Optional[SecurityPolicy],
        key_manager: Optional[KeyManager],
    ) -> Optional[EnvelopeVerifier]:
        """Create envelope verifier from configuration or auto-create if needed."""
        verifier_config = config.get("envelope_verifier")
        from naylence.fame.security.signing.envelope_verifier import (
            EnvelopeVerifierFactory,
        )

        if verifier_config:
            # Explicit configuration - re-raise any exceptions
            return await create_resource(EnvelopeVerifierFactory, verifier_config)

        # Auto-create if policy requires it
        if policy:
            try:
                requirements = policy.requirements()
                should_create_verifier = False
                if requirements:
                    should_create_verifier = requirements.verification_required
                else:
                    # Fallback: check signing config
                    signing_config = getattr(policy, "signing", None)
                    should_create_verifier = bool(signing_config)

                if should_create_verifier:
                    if key_manager is None:
                        raise ValueError("EnvelopeVerifier requires a key manager, but none provided")

                    signing_config = getattr(policy, "signing", None)
                    return await EnvelopeVerifierFactory.create_envelope_verifier(
                        key_provider=key_manager, signing_config=signing_config
                    )
            except Exception as e:
                # Re-raise auto-creation failures for better debugging
                logger.error("failed_to_auto_create_envelope_verifier", exc_info=True)
                raise RuntimeError(f"Failed to auto-create envelope verifier: {e}") from e

        return None

    @classmethod
    async def _create_encryption_manager_from_config(
        cls,
        config: dict,
        policy: Optional[SecurityPolicy],
        key_manager: Optional[KeyManager],
        secure_channel_manager: Optional[SecureChannelManager],
    ) -> tuple[Optional[EncryptionManager], Optional[SecureChannelManager]]:
        """Create encryption manager from configuration or auto-create if needed.

        Returns:
            Tuple of (encryption_manager, secure_channel_manager) where secure_channel_manager
            is either the passed-in one or a newly created one if needed.
        """
        encryption_config = config.get("encryption_manager")
        from naylence.fame.security.encryption.encryption_manager import (
            EncryptionManagerFactory,
        )

        if encryption_config:
            # Explicit configuration - re-raise any exceptions
            if key_manager is None:
                logger.warning("Key provider must be provided to create encryption manager from config")
                return None, secure_channel_manager
            encryption_manager = await create_resource(
                EncryptionManagerFactory, encryption_config, key_provider=key_manager
            )
            return encryption_manager, secure_channel_manager

        # Auto-create if policy requires it
        if policy:
            try:
                requirements = policy.requirements()
                should_create_encryption = False
                if requirements:
                    should_create_encryption = (
                        requirements.encryption_required or requirements.decryption_required
                    )

                if should_create_encryption:
                    from naylence.fame.security.crypto.providers.crypto_provider import (
                        get_crypto_provider,
                    )

                    if secure_channel_manager is None:
                        # Create secure channel manager if not provided
                        from naylence.fame.security.encryption.secure_channel_manager_factory import (
                            SecureChannelManagerFactory,
                        )

                        secure_channel_manager = (
                            await SecureChannelManagerFactory.create_secure_channel_manager({})
                        )

                    if key_manager is None:
                        raise ValueError("KeyManager must be provided to create CompositeEncryptionManager")

                    crypto_provider = get_crypto_provider()
                    encryption_manager = await EncryptionManagerFactory.create_encryption_manager(
                        secure_channel_manager=secure_channel_manager,
                        crypto_provider=crypto_provider,
                        key_provider=key_manager,
                    )
                    return encryption_manager, secure_channel_manager
            except Exception as e:
                # Re-raise auto-creation failures for better debugging
                logger.error("failed_to_auto_create_encryption_manager", exc_info=True)
                raise RuntimeError(f"Failed to auto-create encryption manager: {e}") from e

        return None, secure_channel_manager

    @classmethod
    async def _create_key_manager_from_config(
        cls,
        config: dict,
        policy: Optional[SecurityPolicy],
        key_store: Optional[KeyStore] = None,
    ) -> Optional[KeyManager]:
        """Create key manager from configuration or auto-create if needed."""
        # Use the global key store singleton
        key_store = key_store or config.get("key_store")
        if key_store is None:
            from naylence.fame.security.keys.key_store import get_key_store

            key_store = get_key_store()

        # First try to create from explicit config
        key_manager_config = config.get("key_manager_config")
        if key_manager_config is not None:
            # Explicit configuration - re-raise any exceptions
            return await KeyManagerFactory.create_key_manager(key_manager_config, key_store=key_store)

        # Auto-create with defaults
        try:
            from naylence.fame.security.keys.default_key_manager_factory import (
                DefaultKeyManagerConfig,
            )

            key_manager_config = DefaultKeyManagerConfig()

            # Check if policy requires key manager
            requirements = policy.requirements() if policy else None
            should_create_key_manager = False
            if requirements:
                should_create_key_manager = requirements.require_key_exchange
            else:
                # Fallback: create key manager if no policy requirements available
                should_create_key_manager = True

            if should_create_key_manager:
                return await KeyManagerFactory.create_key_manager(key_manager_config, key_store=key_store)
        except Exception as e:
            # Re-raise auto-creation failures for better debugging
            logger.error("failed_to_auto_create_key_manager", exc_info=True)
            # If we can't determine requirements, create key manager as fallback
            try:
                from naylence.fame.security.keys.default_key_manager_factory import (
                    DefaultKeyManagerConfig,
                )

                fallback_config = DefaultKeyManagerConfig()
                return await KeyManagerFactory.create_key_manager(fallback_config, key_store=key_store)
            except Exception as fallback_error:
                logger.error("failed_to_create_fallback_key_manager", exc_info=True)
                raise RuntimeError(
                    f"Failed to create key manager (fallback also failed): {fallback_error}"
                ) from e

        return None

    @classmethod
    async def _create_authorizer_from_config(
        cls, config: dict, policy: Optional[SecurityPolicy]
    ) -> Optional[Authorizer]:
        """Create authorizer from configuration or auto-create if needed."""
        # First check the new location in security manager config
        authorizer_config = config.get("authorizer")

        # Fall back to legacy location for backward compatibility
        if not authorizer_config:
            authorizer_config = config.get("authorizer_config")

        if authorizer_config:
            # Explicit configuration - re-raise any exceptions
            from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory

            return await create_resource(AuthorizerFactory, authorizer_config)

        # Auto-create by default
        try:
            # Check if policy requires authorization based on requirements
            should_create_authorizer = False
            if policy:
                try:
                    requirements = policy.requirements()
                    if requirements:
                        should_create_authorizer = requirements.require_node_authorization
                    else:
                        # Fallback: default security policy typically requires authorization
                        should_create_authorizer = True
                except (AttributeError, Exception):
                    # Fallback: default security policy typically requires authorization
                    should_create_authorizer = True
            else:
                should_create_authorizer = True

            if should_create_authorizer:
                from naylence.fame.security.auth.authorizer_factory import (
                    AuthorizerFactory,
                )
                from naylence.fame.security.auth.noop_token_verifier import (
                    NoopTokenVerifier,
                )

                # Create a basic authorizer with noop token verifier for default behavior
                token_verifier = NoopTokenVerifier()
                return await AuthorizerFactory.create_authorizer(
                    token_verifier=token_verifier,
                )
        except Exception as e:
            # Re-raise auto-creation failures for better debugging
            logger.error("failed_to_auto_create_authorizer", exc_info=True)
            raise RuntimeError(f"Failed to auto-create authorizer: {e}") from e

        return None

    @classmethod
    async def _create_certificate_manager_from_config(
        cls, config: dict, policy: Optional[SecurityPolicy]
    ) -> Optional[CertificateManager]:
        """Create certificate manager from configuration or auto-create if needed."""

        from naylence.fame.security.cert.certificate_manager_factory import CertificateManagerFactory

        cert_manager_config = config.get("certificate_manager")
        if cert_manager_config:
            # Explicit configuration - re-raise any exceptions
            # Certificate managers might not have a factory pattern yet, implement as needed
            signing = getattr(policy, "signing", None)
            return await CertificateManagerFactory.create_certificate_manager(
                cfg=cert_manager_config,
                signing=signing,
            )

        # Auto-create if policy requires it
        if policy:
            try:
                # Check if policy requires certificate manager based on requirements
                requirements = policy.requirements()
                should_create_certificate_manager = False
                if requirements:
                    should_create_certificate_manager = requirements.require_certificates

                if should_create_certificate_manager:
                    # Try to create certificate manager using default implementation
                    signing = getattr(policy, "signing", None)
                    certificate_manager = await CertificateManagerFactory.create_certificate_manager(
                        signing=signing,
                    )
                    assert certificate_manager, "Failed to create certificate manager"
                    return certificate_manager
            except Exception as e:
                # Re-raise auto-creation failures for better debugging
                logger.error("failed_to_auto_create_certificate_manager", exc_info=True)
                raise RuntimeError(f"Failed to auto-create certificate manager: {e}") from e

        return None

    @classmethod
    async def _create_security_manager(
        cls,
        config: Optional[dict[str, Any]] = None,
        policy: Optional[SecurityPolicy] = None,
        envelope_signer: Optional[EnvelopeSigner] = None,
        envelope_verifier: Optional[EnvelopeVerifier] = None,
        encryption_manager: Optional[EncryptionManager] = None,
        key_store: Optional[KeyStore] = None,
        key_manager: Optional[KeyManager] = None,
        key_validator: Optional[AttachmentKeyValidator] = None,
        authorizer: Optional[Authorizer] = None,
        certificate_manager: Optional[CertificateManager] = None,
        secure_channel_manager: Optional[SecureChannelManager] = None,
        event_listeners: Optional[List[NodeEventListener]] = None,
    ) -> SecurityManager:
        """
        Create SecurityManager with components created from config or auto-created defaults.

        This method handles all component creation logic, including creating components
        from configuration or auto-creating defaults based on policy requirements.

        Args:
            config: Configuration dictionary for creating components from configs
            policy: Security policy (created from config or defaults to DefaultSecurityPolicy if None)
            envelope_signer: Envelope signer (created from config or auto-created if None and required)
            envelope_verifier: Envelope verifier (created from config or auto-created if None and required)
            encryption_manager: Encryption manager (created from config
                or auto-created if None and required)
            key_manager: Key manager (created from config or auto-created if None and required)
            authorizer: Node attach authorizer (created from config or auto-created if None)
            certificate_manager: Certificate manager (created from config
                or auto-created if None and required)
            secure_channel_manager: Secure channel manager (created if needed for encryption)

        Returns:
            Configured SecurityManager instance with appropriate components
        """
        if config is None:
            config = {}

        # Create policy first to determine requirements
        if policy is None:
            policy = await cls._create_policy_from_config(config, key_provider=key_store)

        # Create key manager if needed - it's often required by other components
        if key_manager is None:
            key_manager = await cls._create_key_manager_from_config(config, policy, key_store=key_store)

        # # Recreate policy with key_provider if we now have a key_manager and policy config exists
        # if key_manager is not None and config.get("security_policy"):
        #     policy = await cls._create_policy_from_config(config, key_provider=key_manager)

        # Create other components from config or auto-create based on policy requirements
        if envelope_signer is None:
            envelope_signer = await cls._create_envelope_signer_from_config(config, policy)

        if envelope_verifier is None:
            envelope_verifier = await cls._create_envelope_verifier_from_config(config, policy, key_manager)

        if encryption_manager is None:
            encryption_manager, secure_channel_manager = await cls._create_encryption_manager_from_config(
                config, policy, key_manager, secure_channel_manager
            )

        if authorizer is None:
            authorizer = await cls._create_authorizer_from_config(config, policy)
            if event_listeners is not None and isinstance(authorizer, NodeEventListener):
                event_listeners.append(authorizer)

        if certificate_manager is None:
            certificate_manager = await cls._create_certificate_manager_from_config(config, policy)

        # Ensure we have at least a default policy
        if policy is None:
            from naylence.fame.security.policy.default_security_policy import (
                DefaultSecurityPolicy,
            )

            policy = DefaultSecurityPolicy()

        from naylence.fame.security.default_security_manager import (
            DefaultSecurityManager,
        )

        return DefaultSecurityManager(
            policy=policy,
            envelope_signer=envelope_signer,
            envelope_verifier=envelope_verifier,
            encryption=encryption_manager,
            key_manager=key_manager,
            key_validator=key_validator,
            authorizer=authorizer,
            certificate_manager=certificate_manager,
            secure_channel_manager=secure_channel_manager,
        )
