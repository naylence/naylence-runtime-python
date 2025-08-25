"""
No-security policy implementation for testing or development environments.
"""

from typing import TYPE_CHECKING, Optional

from naylence.fame.core import FameDeliveryContext, FameEnvelope

from ..encryption.encryption_manager import EncryptionOptions
from .security_policy import (
    CryptoLevel,
    SecurityAction,
    SecurityPolicy,
    SecurityRequirements,
)

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike


class NoSecurityPolicy(SecurityPolicy):
    """No-security policy for testing or development environments."""

    async def should_sign_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional["NodeLike"] = None,
    ) -> bool:
        return False

    async def should_encrypt_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional["NodeLike"] = None,
    ) -> bool:
        return False

    async def get_encryption_options(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional["NodeLike"] = None,
    ) -> Optional[EncryptionOptions]:
        return None

    async def should_verify_signature(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        return False

    async def should_decrypt_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional["NodeLike"] = None,
    ) -> bool:
        return envelope.sec is not None and envelope.sec.enc is not None  # Always decrypt if encrypted

    # New flexible security policy methods

    def classify_message_crypto_level(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> CryptoLevel:
        """Always classify as plaintext since this is a no-security policy."""
        return CryptoLevel.PLAINTEXT

    def is_inbound_crypto_level_allowed(
        self,
        crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> bool:
        """Allow all crypto levels in no-security mode."""
        return True

    def get_inbound_violation_action(
        self,
        crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> SecurityAction:
        """Always allow in no-security mode."""
        return SecurityAction.ALLOW

    async def decide_response_crypto_level(
        self,
        request_crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> CryptoLevel:
        """Always use plaintext for responses in no-security mode."""
        return CryptoLevel.PLAINTEXT

    async def decide_outbound_crypto_level(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional["NodeLike"] = None,
    ) -> CryptoLevel:
        """Always use plaintext for outbound messages in no-security mode."""
        return CryptoLevel.PLAINTEXT

    def is_signature_required(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        """Signatures are never required in no-security mode."""
        return False

    def get_unsigned_violation_action(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> SecurityAction:
        """Always allow unsigned messages in no-security mode."""
        return SecurityAction.ALLOW

    def get_invalid_signature_violation_action(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> SecurityAction:
        """Always allow invalid signatures in no-security mode."""
        return SecurityAction.ALLOW

    def requirements(self) -> SecurityRequirements:
        """Get the security requirements for no-security policy."""
        return SecurityRequirements(
            signing_required=False,
            verification_required=False,
            encryption_required=False,
            decryption_required=False,
            minimum_crypto_level=CryptoLevel.PLAINTEXT,
            supported_signing_algorithms=frozenset(),
            supported_encryption_algorithms=frozenset(),
            preferred_signing_algorithm=None,
            preferred_encryption_algorithm=None,
        )
