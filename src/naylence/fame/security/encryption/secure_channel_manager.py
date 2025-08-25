from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, NamedTuple, Optional

if TYPE_CHECKING:
    from naylence.fame.core import (
        DataFrame,
        SecureAcceptFrame,
        SecureCloseFrame,
        SecureOpenFrame,
    )


class SecureChannelState(NamedTuple):
    """State for an active secure channel."""

    key: bytes
    send_counter: int
    recv_counter: int
    nonce_prefix: bytes  # 4-byte random prefix for ChaCha20Poly1305
    expires_at: float
    algorithm: str


class SecureChannelManager(ABC):
    """Abstract interface for secure channel managers.

    This interface defines the contract for managing secure channels using
    cryptographic protocols for secure communication between nodes.
    """

    @property
    @abstractmethod
    def channels(self) -> Dict[str, SecureChannelState]:
        """Get the current active channels.

        Returns:
            Dictionary mapping channel IDs to their states
        """
        ...

    @abstractmethod
    def generate_open_frame(self, cid: str, algorithm: str = "CHACHA20P1305") -> SecureOpenFrame:
        """Generate a SecureOpenFrame to initiate a channel.

        Args:
            cid: Channel identifier
            algorithm: Encryption algorithm to use

        Returns:
            SecureOpenFrame for channel initiation
        """
        ...

    @abstractmethod
    async def handle_open_frame(self, frame: SecureOpenFrame) -> SecureAcceptFrame:
        """Handle incoming SecureOpenFrame and generate response.

        Args:
            frame: The incoming SecureOpenFrame

        Returns:
            SecureAcceptFrame response
        """
        ...

    @abstractmethod
    async def handle_accept_frame(self, frame: SecureAcceptFrame) -> bool:
        """Handle incoming SecureAcceptFrame to complete handshake.

        Args:
            frame: The incoming SecureAcceptFrame

        Returns:
            True if handshake completed successfully, False otherwise
        """
        ...

    @abstractmethod
    def handle_close_frame(self, frame: SecureCloseFrame) -> None:
        """Handle channel close.

        Args:
            frame: The SecureCloseFrame
        """
        ...

    @abstractmethod
    def is_channel_encrypted(self, df: DataFrame) -> bool:
        """Check if a DataFrame is channel encrypted.

        Args:
            df: The DataFrame to check

        Returns:
            True if the DataFrame is channel encrypted
        """
        ...

    @abstractmethod
    def has_channel(self, cid: str) -> bool:
        """Check if we have an active channel.

        Args:
            cid: Channel identifier

        Returns:
            True if channel exists and is active
        """
        ...

    @abstractmethod
    def get_channel_info(self, cid: str) -> Optional[Dict]:
        """Get channel information for debugging.

        Args:
            cid: Channel identifier

        Returns:
            Dictionary with channel information or None if channel doesn't exist
        """
        ...

    @abstractmethod
    def close_channel(self, cid: str, reason: str = "User requested") -> SecureCloseFrame:
        """Close a channel and return close frame.

        Args:
            cid: Channel identifier
            reason: Reason for closing the channel

        Returns:
            SecureCloseFrame for the closed channel
        """
        ...

    @abstractmethod
    def cleanup_expired_channels(self) -> int:
        """Remove expired channels.

        Returns:
            Number of channels cleaned up
        """
        ...

    @abstractmethod
    def add_channel(self, cid: str, channel_state: SecureChannelState) -> None:
        """Add a channel to the manager.

        Args:
            cid: Channel identifier
            channel_state: The channel state to add
        """
        ...

    @abstractmethod
    def remove_channel(self, cid: str) -> bool:
        """Remove a channel from the manager.

        Args:
            cid: Channel identifier

        Returns:
            True if channel was removed, False if it didn't exist
        """
        ...
