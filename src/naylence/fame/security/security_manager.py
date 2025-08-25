from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional

from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.encryption.encryption_manager import EncryptionManager
from naylence.fame.security.policy import SecurityPolicy
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
    from naylence.fame.node.secure_channel_frame_handler import (
        SecureChannelFrameHandler,
    )
    from naylence.fame.security.auth.authorizer import Authorizer
    from naylence.fame.security.cert.certificate_manager import CertificateManager
    from naylence.fame.security.keys.key_manager import KeyManager

logger = getLogger(__name__)


class SecurityManager(NodeEventListener, ABC):
    """
    Abstract interface for node security managers.

    This interface defines the contract for managing all security-related components
    and operations for a node. Implementations should handle:
    - Security policy enforcement
    - Envelope signing and verification
    - Encryption and decryption
    - Key management
    - Authorization
    - Certificate management
    """

    @property
    @abstractmethod
    def policy(self) -> SecurityPolicy:
        """Get the security policy."""
        ...

    @property
    @abstractmethod
    def envelope_signer(self) -> Optional[EnvelopeSigner]:
        """Get the envelope signer."""
        ...

    @property
    @abstractmethod
    def envelope_verifier(self) -> Optional[EnvelopeVerifier]:
        """Get the envelope verifier."""
        ...

    @property
    @abstractmethod
    def encryption(self) -> Optional[EncryptionManager]:
        """Get the encryption manager."""
        ...

    @property
    @abstractmethod
    def key_manager(self) -> Optional[KeyManager]:
        """Get the key manager."""
        ...

    @property
    @abstractmethod
    def supports_overlay_security(self) -> bool:
        """Check if key sharing is supported."""
        ...

    @property
    @abstractmethod
    def authorizer(self) -> Optional[Authorizer]:
        """Get the node attach authorizer."""
        ...

    @property
    @abstractmethod
    def certificate_manager(self) -> Optional[CertificateManager]:
        """Get the certificate manager."""
        ...

    @property
    @abstractmethod
    def envelope_security_handler(self) -> Optional[EnvelopeSecurityHandler]:
        """Get the envelope security handler."""
        ...

    @property
    @abstractmethod
    def secure_channel_frame_handler(self) -> Optional[SecureChannelFrameHandler]:
        """Get the channel frame handler."""
        ...

    @abstractmethod
    def get_encryption_key_id(self) -> Optional[str]:
        """Get the encryption key ID from the crypto provider."""
        ...

    @abstractmethod
    def get_shareable_keys(self) -> Any:
        """Get keys to provide to child nodes."""
        return None
