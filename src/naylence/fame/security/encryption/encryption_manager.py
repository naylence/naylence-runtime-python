"""
EncryptionManager: Handles overlay encryption (sealed envelopes, secure channels) for Naylence nodes.

Responsibilities:
- Orchestrate secure channel handshakes (SecureOpen, SecureAccept, SecureClose)
- Maintain a registry of open channels
- Encrypt/decrypt envelope payloads as needed
- Apply security policy based on path, flags, or agent request
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, List, Optional, TypedDict

from naylence.fame.core import FameEnvelope
from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource

if TYPE_CHECKING:
    from naylence.fame.core import FameAddress

FIXED_PREFIX_LEN = 44  # 32-byte eph_pub + 12-byte nonce


class EncryptionOptions(TypedDict, total=False):
    recip_pub: bytes
    priv_key: bytes
    channel_key: bytes
    nonce: bytes
    recip_kid: str  # Recipient key ID
    request_address: "FameAddress"  # Address to request key for (when key ID is unknown)
    encryption_type: str  # Type of encryption: "standard" or "channel"
    destination: "FameAddress"  # Destination address for channel encryption
    # ...future fields...


class EncryptionStatus(Enum):
    """Status of encryption operation."""

    OK = auto()  # envelope is encrypted and ready for delivery
    SKIPPED = auto()  # encryption not needed/applicable
    QUEUED = auto()  # envelope queued, prerequisite fulfillment in progress


@dataclass
class EncryptionResult:
    """Result of encryption operation."""

    def __init__(self, status: EncryptionStatus, envelope: Optional[FameEnvelope]):
        self.status = status
        self.envelope = envelope

    @classmethod
    def ok(cls, envelope: FameEnvelope) -> "EncryptionResult":
        """Create a successful encryption result."""
        return cls(EncryptionStatus.OK, envelope)

    @classmethod
    def skipped(cls, envelope: FameEnvelope) -> "EncryptionResult":
        """Create a skipped encryption result."""
        return cls(EncryptionStatus.SKIPPED, envelope)

    @classmethod
    def queued(cls) -> "EncryptionResult":
        """Create a queued encryption result."""
        return cls(EncryptionStatus.QUEUED, None)


class EncryptionManager(ABC):
    def __init__(self, node_static_pub: Optional[bytes] = None):
        self.node_static_pub = node_static_pub

    @abstractmethod
    async def encrypt_envelope(
        self,
        env: FameEnvelope,
        *,
        opts: Optional[EncryptionOptions] = None,
    ) -> EncryptionResult:
        """
        Encrypt envelope asynchronously.

        This method implements a unified contract for all encryption types:
        - Checks prerequisites (keys, channels, etc.)
        - If missing: initiates fulfillment process and queues envelope
        - If ready: encrypts envelope immediately

        Returns:
            EncryptionResult with:
            - OK: envelope encrypted and ready for delivery
            - SKIPPED: encryption not needed/applicable, envelope unchanged
            - QUEUED: envelope queued, prerequisite fulfillment in progress
        """
        pass

    @abstractmethod
    async def decrypt_envelope(
        self,
        env: FameEnvelope,
        *,
        opts: Optional[EncryptionOptions] = None,
    ) -> FameEnvelope:
        """
        Decrypt envelope asynchronously.

        Returns the decrypted envelope, or the original envelope if decryption
        is not needed/applicable.
        """
        pass

    async def notify_channel_established(self, channel_id: str) -> None:
        """
        Notify the encryption manager that a channel handshake has completed.

        This is an optional method that can be implemented by encryption managers
        that need to track channel establishment (e.g., ChannelEncryptionManager).

        When a channel becomes available, the manager should process any queued
        envelopes for that channel.

        Args:
            channel_id: The ID of the channel that was established
        """
        # Default implementation does nothing
        pass


class EncryptionManagerConfig(ResourceConfig):
    """Common config fields for all EncryptionManager implementations."""

    type: str = "EncryptionManager"  # Default type, can be overridden by subclasses
    supported_algorithms: Optional[List[str]] = None
    encryption_type: Optional[str] = None  # "sealed", "channel", etc.
    priority: int = 0  # Higher priority factories are preferred for algorithm conflicts


class EncryptionManagerFactory(ResourceFactory[EncryptionManager, EncryptionManagerConfig]):
    """Abstract resource-factory for EncryptionManager objects (pluggable algos)."""

    @abstractmethod
    def get_supported_algorithms(self) -> List[str]:
        """Return list of algorithms this factory can create managers for."""
        pass

    @abstractmethod
    def get_encryption_type(self) -> str:
        """Return the encryption type this factory handles (sealed, channel, etc.)."""
        pass

    @abstractmethod
    def supports_options(self, opts: Optional[EncryptionOptions]) -> bool:
        """Check if this factory can handle the given encryption options."""
        pass

    def get_priority(self) -> int:
        """Return priority for algorithm conflicts (higher = preferred)."""
        # Default priority, can be overridden by subclasses
        return 0

    @classmethod
    async def create_encryption_manager(
        cls,
        cfg: Optional[EncryptionManagerConfig | dict[str, Any]] = None,
        *,
        secure_channel_manager=None,
        crypto_provider=None,
        key_provider=None,
        **kwargs,
    ) -> Optional[EncryptionManager]:
        """Create an EncryptionManager instance based on the provided configuration."""

        if isinstance(cfg, EncryptionManagerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(
            EncryptionManagerFactory,
            cfg_dict,
            secure_channel_manager=secure_channel_manager,
            crypto_provider=crypto_provider,
            key_provider=key_provider,
            **kwargs,
        )
