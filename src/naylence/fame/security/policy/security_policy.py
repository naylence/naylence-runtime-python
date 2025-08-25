"""
Base security policy interfaces and configuration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, FrozenSet, List, Optional

from pydantic import ConfigDict, Field, model_validator

from naylence.fame.core import (
    ExpressionEnabledModel,
    FameDeliveryContext,
    FameEnvelope,
    ResourceConfig,
)

from ..encryption.encryption_manager import EncryptionOptions

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike


class CryptoLevel(Enum):
    """Classification of message encryption levels."""

    PLAINTEXT = "plaintext"  # No encryption (unencrypted payload, no secure transport)
    CHANNEL = "channel"  # Transport-level encryption only (TLS, mTLS, secure WebSocket)
    SEALED = "sealed"  # End-to-end encrypted payload (envelope-level encryption)

    @property
    def security_order(self) -> int:
        """Return the security order for comparison (higher = more secure)."""
        if self == CryptoLevel.PLAINTEXT:
            return 1
        elif self == CryptoLevel.CHANNEL:
            return 2
        elif self == CryptoLevel.SEALED:
            return 3
        else:
            return 0

    def __lt__(self, other) -> bool:
        if not isinstance(other, CryptoLevel):
            return NotImplemented
        return self.security_order < other.security_order

    def __le__(self, other) -> bool:
        if not isinstance(other, CryptoLevel):
            return NotImplemented
        return self.security_order <= other.security_order

    def __gt__(self, other) -> bool:
        if not isinstance(other, CryptoLevel):
            return NotImplemented
        return self.security_order > other.security_order

    def __ge__(self, other) -> bool:
        if not isinstance(other, CryptoLevel):
            return NotImplemented
        return self.security_order >= other.security_order


class SecurityAction(Enum):
    """Actions to take when security policies are violated."""

    ALLOW = "allow"  # Allow the message to proceed
    REJECT = "reject"  # Reject with error response
    NACK = "nack"  # Send a negative acknowledgment


class SignaturePolicy(Enum):
    """Signature verification policy for inbound messages."""

    REQUIRED = "required"  # All messages must be signed and verified
    OPTIONAL = "optional"  # Verify signatures if present, allow unsigned
    DISABLED = "disabled"  # Don't verify signatures (even if present)
    FORBIDDEN = "forbidden"  # Reject signed messages (for debugging)


class SigningMaterial(StrEnum):
    """Type of cryptographic evidence used for signing envelopes."""

    RAW_KEY = "raw-key"  # Default: JWK-based signing
    X509_CHAIN = "x509-chain"  # CA-signed certificate chain for signing


class SecurityPolicyConfig(ResourceConfig):
    """Base configuration for security policies."""

    type: str = "SecurityPolicy"

    model_config = {"arbitrary_types_allowed": True}


class SecurityPolicy(ABC):
    """Abstract interface for node security policies."""

    @abstractmethod
    async def should_sign_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should be signed."""
        pass

    @abstractmethod
    async def should_encrypt_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should be encrypted."""
        pass

    @abstractmethod
    async def get_encryption_options(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> Optional[EncryptionOptions]:
        """Get encryption options (recipient key, etc.) for the envelope."""
        pass

    @abstractmethod
    async def should_verify_signature(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        """Determine if an envelope's signature should be verified."""
        pass

    @abstractmethod
    async def should_decrypt_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should be decrypted."""
        pass

    # New flexible security policy methods

    @abstractmethod
    def classify_message_crypto_level(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> CryptoLevel:
        """Classify the encryption level of an incoming message."""
        pass

    @abstractmethod
    def is_inbound_crypto_level_allowed(
        self,
        crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> bool:
        """Check if an inbound message's crypto level is allowed by policy."""
        pass

    @abstractmethod
    def get_inbound_violation_action(
        self,
        crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> SecurityAction:
        """Get the action to take when inbound crypto level violates policy."""
        pass

    @abstractmethod
    async def decide_response_crypto_level(
        self,
        request_crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> CryptoLevel:
        """Determine what crypto level to use for a response based on the original request."""
        pass

    @abstractmethod
    async def decide_outbound_crypto_level(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> CryptoLevel:
        """Determine what crypto level to use for a new outbound request (not a response)."""
        pass

    @abstractmethod
    def is_signature_required(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        """Check if an inbound message must have a signature."""
        pass

    @abstractmethod
    def get_unsigned_violation_action(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> SecurityAction:
        """Get the action to take when a required signature is missing."""
        pass

    @abstractmethod
    def get_invalid_signature_violation_action(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> SecurityAction:
        """Get the action to take when signature verification fails."""
        pass

    @abstractmethod
    def requirements(self) -> SecurityRequirements:
        """Get the security requirements of this policy."""
        pass

    def validate_attach_security_compatibility(
        self,
        peer_keys: Optional[list[dict]] = None,
        peer_requirements: Optional[SecurityRequirements] = None,
        node_like: Optional[NodeLike] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Validate that the attach handshake satisfies security policy requirements.

        Args:
            peer_keys: Keys provided by the peer during attach
            peer_requirements: Peer's security requirements (if known)
            node_like: The node context for additional validation

        Returns:
            (is_valid, reason) - True if compatible, False with reason if not
        """
        requirements = self.requirements()

        # Check if we require signing key exchange and peer provided signing keys
        if requirements.require_signing_key_exchange:
            if not peer_keys:
                return (
                    False,
                    "Policy requires signing key exchange but no keys provided",
                )

            # Check if peer keys contain signing keys
            has_signing_key = any(
                key.get("use") in ["sig", None] and key.get("kty") == "OKP" and key.get("crv") == "Ed25519"
                for key in peer_keys
            )
            if not has_signing_key:
                return (
                    False,
                    "Policy requires signing key exchange but no signing keys provided",
                )

        # Check if we require encryption key exchange and peer provided encryption keys
        if requirements.require_encryption_key_exchange:
            if not peer_keys:
                return (
                    False,
                    "Policy requires encryption key exchange but no keys provided",
                )

            # Check if peer keys contain encryption keys
            has_encryption_key = any(
                key.get("use") in ["enc", None] and key.get("kty") == "OKP" and key.get("crv") == "X25519"
                for key in peer_keys
            )
            if not has_encryption_key:
                return (
                    False,
                    "Policy requires encryption key exchange but no encryption keys provided",
                )

        # If peer requirements are provided, validate compatibility
        if peer_requirements:
            # Check minimum crypto level compatibility
            if peer_requirements.minimum_crypto_level > requirements.minimum_crypto_level:
                # Peer requires higher security than we support - check if we can meet it
                if (
                    peer_requirements.minimum_crypto_level == CryptoLevel.SEALED
                    and not requirements.encryption_required
                ):
                    return (
                        False,
                        f"Peer requires {peer_requirements.minimum_crypto_level.name} "
                        "but we don't support encryption",
                    )
                elif (
                    peer_requirements.minimum_crypto_level == CryptoLevel.CHANNEL
                    and requirements.minimum_crypto_level == CryptoLevel.PLAINTEXT
                ):
                    # We support plaintext but peer requires at least channel "
                    # "- this is usually OK as transport can provide channel security
                    pass

            # Check algorithm compatibility for signing
            if peer_requirements.signing_required and requirements.verification_required:
                common_signing_algs = (
                    requirements.supported_signing_algorithms
                    & peer_requirements.supported_signing_algorithms
                )
                if not common_signing_algs:
                    return (
                        False,
                        f"No compatible signing algorithms: peer supports {
                            peer_requirements.supported_signing_algorithms
                        }, we support {requirements.supported_signing_algorithms}",
                    )

            # Check algorithm compatibility for encryption
            if peer_requirements.encryption_required and requirements.decryption_required:
                common_encryption_algs = (
                    requirements.supported_encryption_algorithms
                    & peer_requirements.supported_encryption_algorithms
                )
                if not common_encryption_algs:
                    return (
                        False,
                        f"No compatible encryption algorithms: peer supports {
                            peer_requirements.supported_encryption_algorithms
                        }, we support {requirements.supported_encryption_algorithms}",
                    )

        return True, None


class InboundCryptoRules(ExpressionEnabledModel):
    """Configuration for handling inbound messages with different crypto levels."""

    allow_plaintext: bool = Field(default=True, description="Allow unencrypted messages")
    allow_channel: bool = Field(default=True, description="Allow transport-encrypted messages (TLS/mTLS)")
    allow_sealed: bool = Field(default=True, description="Allow end-to-end encrypted messages")
    # Actions to take when crypto level is not allowed
    plaintext_violation_action: SecurityAction = Field(default=SecurityAction.NACK)
    channel_violation_action: SecurityAction = Field(default=SecurityAction.NACK)
    sealed_violation_action: SecurityAction = Field(default=SecurityAction.NACK)


class ResponseCryptoRules(ExpressionEnabledModel):
    """Configuration for response encryption behavior."""

    mirror_request_level: bool = Field(default=True, description="Match response encryption to request")
    minimum_response_level: CryptoLevel = Field(
        default=CryptoLevel.CHANNEL, description="Minimum security for responses"
    )
    escalate_sealed_responses: bool = Field(
        default=False, description="Always use SEALED for responses if possible"
    )


class OutboundCryptoRules(ExpressionEnabledModel):
    """Configuration for new outbound request encryption."""

    default_level: CryptoLevel = Field(
        default=CryptoLevel.CHANNEL, description="Default encryption for new requests"
    )
    escalate_if_peer_supports: bool = Field(
        default=True, description="Upgrade to SEALED if recipient has keys"
    )
    prefer_sealed_for_sensitive: bool = Field(
        default=True, description="Use SEALED for sensitive operations"
    )


class EncryptionConfig(ExpressionEnabledModel):
    """Complete configuration for flexible crypto security policies."""

    # Supported algorithm lists for classification
    supported_channel_algorithms: List[str] = Field(
        default_factory=lambda: ["chacha20-poly1305-channel"],
        description="List of algorithms considered as channel encryption",
    )
    supported_sealed_algorithms: List[str] = Field(
        default_factory=lambda: ["chacha20-poly1305", "aes-256-gcm", "ECDH-ES+A256GCM"],
        description="List of algorithms considered as sealed/envelope encryption",
    )

    inbound: InboundCryptoRules = Field(default_factory=InboundCryptoRules)
    response: ResponseCryptoRules = Field(default_factory=ResponseCryptoRules)
    outbound: OutboundCryptoRules = Field(default_factory=OutboundCryptoRules)

    @classmethod
    def for_development(cls) -> EncryptionConfig:
        """Create an encryption config suitable for development/basic framework use.

        This creates a PLAINTEXT-only configuration that:
        - Only allows PLAINTEXT messages (no encryption required)
        - Uses PLAINTEXT for all outbound messages
        - Doesn't require any encryption components
        """
        return cls(
            inbound=InboundCryptoRules(
                allow_plaintext=True,
                allow_channel=False,  # No encryption support
                allow_sealed=False,  # No encryption support
                plaintext_violation_action=SecurityAction.ALLOW,
            ),
            outbound=OutboundCryptoRules(
                default_level=CryptoLevel.PLAINTEXT,
                escalate_if_peer_supports=False,
                prefer_sealed_for_sensitive=False,
            ),
            response=ResponseCryptoRules(
                minimum_response_level=CryptoLevel.PLAINTEXT,
                mirror_request_level=False,  # Don't mirror - always use PLAINTEXT
                escalate_sealed_responses=False,
            ),
        )

    # Supported algorithms for each crypto level (for classification flexibility)
    plaintext_algorithms: List[str] = Field(
        default_factory=list, description="Supported algorithms for PLAINTEXT"
    )
    channel_algorithms: List[str] = Field(
        default_factory=list, description="Supported algorithms for CHANNEL"
    )
    sealed_algorithms: List[str] = Field(
        default_factory=list, description="Supported algorithms for SEALED"
    )


class InboundSigningRules(ExpressionEnabledModel):
    """Configuration for handling inbound message signature verification."""

    signature_policy: SignaturePolicy = Field(
        default=SignaturePolicy.OPTIONAL, description="Signature verification policy"
    )
    # Actions to take when signing requirements are not met
    unsigned_violation_action: SecurityAction = Field(default=SecurityAction.ALLOW)
    invalid_signature_action: SecurityAction = Field(default=SecurityAction.REJECT)
    missing_key_action: SecurityAction = Field(default=SecurityAction.NACK)


class ResponseSigningRules(ExpressionEnabledModel):
    """Configuration for response signing behavior."""

    mirror_request_signing: bool = Field(default=False, description="Sign response if request was signed")
    always_sign_responses: bool = Field(default=False, description="Always sign responses")
    sign_error_responses: bool = Field(default=False, description="Sign error responses")


class OutboundSigningRules(ExpressionEnabledModel):
    """Configuration for new outbound request signing."""

    default_signing: bool = Field(default=False, description="Sign new outbound requests by default")
    sign_sensitive_operations: bool = Field(default=False, description="Always sign sensitive operations")
    sign_if_recipient_expects: bool = Field(default=True, description="Sign if recipient policy expects it")


class SigningConfig(ExpressionEnabledModel):
    """Complete configuration for message signing policies."""

    inbound: InboundSigningRules = Field(default_factory=InboundSigningRules)
    response: ResponseSigningRules = Field(default_factory=ResponseSigningRules)
    outbound: OutboundSigningRules = Field(default_factory=OutboundSigningRules)

    signing_material: SigningMaterial = Field(
        default=SigningMaterial.RAW_KEY,
        description="RAW_KEY → plain JWKs, X509_CHAIN → CA-signed chain",
    )

    @classmethod
    def for_development(cls) -> SigningConfig:
        """Create a signing config suitable for development/basic framework use.

        This creates a configuration that:
        - Doesn't require signing by default
        - Allows optional signature verification when present
        - Doesn't assume recipients expect signatures
        """
        return cls(
            inbound=InboundSigningRules(
                # Completely disable signature verification for basic use
                signature_policy=SignaturePolicy.DISABLED,
                unsigned_violation_action=SecurityAction.ALLOW,
                invalid_signature_action=SecurityAction.REJECT,
                missing_key_action=SecurityAction.ALLOW,  # Don't require keys for verification
            ),
            outbound=OutboundSigningRules(
                default_signing=False,
                sign_sensitive_operations=False,
                sign_if_recipient_expects=False,  # Don't assume recipients expect signatures
            ),
            response=ResponseSigningRules(
                mirror_request_signing=False,  # Don't mirror by default
                always_sign_responses=False,
                sign_error_responses=False,
            ),
            signing_material=SigningMaterial.RAW_KEY,
        )

    # X.509 validation knobs (used only when signing_material == X509_CHAIN)
    validate_cert_name_constraints: bool = Field(
        default=True,
        description="Validate NameConstraints / SAN URIs in peer certificates",
    )
    # CA trust store is now always sourced from FAME_CA_CERTS env var
    # Remove trust_store_path; all validation uses FAME_CA_CERTS
    require_cert_sid_match: bool = Field(
        default=False, description="Envelope SID must match certificate SID"
    )
    require_cert_logical_match: bool = Field(
        default=False, description="Logical must be permitted by certificate SAN URIs"
    )

    @model_validator(mode="after")
    def _check_consistency(self) -> SigningConfig:
        if self.signing_material == SigningMaterial.RAW_KEY:
            # In RAW_KEY mode all X.509-specific flags must stay at defaults
            if (
                self.validate_cert_name_constraints is not True
                or self.require_cert_sid_match is not False
                or self.require_cert_logical_match is not False
            ):
                raise ValueError("X.509 validation options present but signing_material is RAW_KEY")
        return self


class SecurityRequirements(ExpressionEnabledModel):
    """Declarative requirements that a security policy needs from security components."""

    model_config = ConfigDict(frozen=True)

    # Signing requirements
    signing_required: bool = Field(default=False, description="Whether signing capability is required")
    verification_required: bool = Field(
        default=False, description="Whether signature verification is required"
    )
    supported_signing_algorithms: FrozenSet[str] = Field(
        default_factory=lambda: frozenset(["EdDSA"]),
        description="Supported signing algorithms",
    )

    # Encryption requirements
    encryption_required: bool = Field(
        default=False, description="Whether encryption capability is required"
    )
    decryption_required: bool = Field(
        default=False, description="Whether decryption capability is required"
    )
    supported_encryption_algorithms: FrozenSet[str] = Field(
        default_factory=lambda: frozenset(["X25519", "ChaCha20Poly1305"]),
        description="Supported encryption algorithms",
    )

    # Key management requirements (granular)
    require_key_exchange: bool = Field(
        default=False, description="Whether key exchange and management is required"
    )
    require_signing_key_exchange: bool = Field(
        default=False,
        description="Whether signing key exchange is required during attach",
    )
    require_encryption_key_exchange: bool = Field(
        default=False,
        description="Whether encryption key exchange is required during attach",
    )

    # Node authorization requirements
    require_node_authorization: bool = Field(
        default=False,
        description="Whether node authorization is required for node attachment",
    )

    # Certificate management requirements
    require_certificates: bool = Field(
        default=False,
        description="Whether certificate management is required (e.g., for X.509 chains)",
    )

    # Minimum security levels
    minimum_crypto_level: CryptoLevel = Field(
        default=CryptoLevel.PLAINTEXT, description="Minimum required crypto level"
    )

    # Optional preferences (for auto-selection)
    preferred_signing_algorithms: List[str] = Field(
        default_factory=lambda: ["EdDSA"],
        description="Ordered list of preferred signing algorithms",
    )
    preferred_encryption_algorithms: List[str] = Field(
        default_factory=lambda: ["X25519", "ChaCha20Poly1305"],
        description="Ordered list of preferred encryption algorithms",
    )

    # Backward compatibility - single preferred algorithm (deprecated)
    preferred_signing_algorithm: Optional[str] = Field(
        default="EdDSA",
        description="Single preferred signing algorithm (deprecated, use preferred_signing_algorithms)",
    )
    preferred_encryption_algorithm: Optional[str] = Field(
        default="X25519",
        description="Single preferred encryption algorithm (deprecated, "
        "use preferred_encryption_algorithms)",
    )
