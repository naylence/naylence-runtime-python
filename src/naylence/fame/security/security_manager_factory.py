from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, TypeVar

from naylence.fame.factory import ResourceFactory, create_default_resource
from naylence.fame.security.encryption.encryption_manager import EncryptionManager
from naylence.fame.security.encryption.secure_channel_manager import (
    SecureChannelManager,
)
from naylence.fame.security.policy.security_policy import SecurityPolicy
from naylence.fame.security.security_manager_config import SecurityManagerConfig
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier

from .security_manager import SecurityManager

if TYPE_CHECKING:
    from naylence.fame.security.auth.authorizer import Authorizer
    from naylence.fame.security.cert.certificate_manager import CertificateManager
    from naylence.fame.security.keys.key_manager import KeyManager

# Type variables for the factory pattern
C = TypeVar("C", bound=SecurityManagerConfig)


class SecurityManagerFactory(ResourceFactory[SecurityManager, C]):
    """Abstract ResourceFactory for creating SecurityManager instances."""

    async def create(self, config: Optional[C | dict[str, Any]] = None, **kwargs: Any) -> SecurityManager:
        """Create a SecurityManager instance."""
        raise NotImplementedError

    @classmethod
    async def create_security_manager(
        cls,
        policy: Optional[SecurityPolicy] = None,
        envelope_signer: Optional[EnvelopeSigner] = None,
        envelope_verifier: Optional[EnvelopeVerifier] = None,
        encryption_manager: Optional[EncryptionManager] = None,
        key_manager: Optional[KeyManager] = None,
        authorizer: Optional[Authorizer] = None,
        certificate_manager: Optional[CertificateManager] = None,
        secure_channel_manager: Optional[SecureChannelManager] = None,
    ) -> SecurityManager:
        from naylence.fame.security.security_manager_factory import (
            SecurityManagerFactory,
        )

        result = await create_default_resource(
            SecurityManagerFactory,
            config=None,
            policy=policy,
            envelope_signer=envelope_signer,
            envelope_verifier=envelope_verifier,
            encryption_manager=encryption_manager,
            key_manager=key_manager,
            authorizer=authorizer,
            certificate_manager=certificate_manager,
            secure_channel_manager=secure_channel_manager,
        )

        assert result is not None, "Failed to create SecurityManager instance"

        return result
