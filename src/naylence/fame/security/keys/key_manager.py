"""
Key management interfaces and global factory functions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, Optional

from naylence.fame.core import (
    DeliveryOriginType,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.keys.key_provider import KeyProvider


class KeyManager(ABC, NodeEventListener, KeyProvider):
    """Abstract interface for key management."""

    @abstractmethod
    async def get_key(self, kid: str) -> dict[str, Any]:
        pass

    @abstractmethod
    async def has_key(self, kid: str) -> bool:
        """Check if a key with the given key ID exists."""
        pass

    @abstractmethod
    async def add_keys(
        self,
        *,
        keys: list[dict],
        sid: Optional[str] = None,
        physical_path: str,
        system_id: str,
        origin: DeliveryOriginType,
        skip_sid_validation: bool = False,
    ):
        """Add keys to the key manager."""
        pass

    @abstractmethod
    async def announce_keys_to_upstream(self):
        """Announce keys to upstream nodes."""
        pass

    @abstractmethod
    async def handle_key_request(
        self,
        kid: str,
        from_seg: str,
        *,
        physical_path: str | None,
        origin: DeliveryOriginType,
        corr_id: Optional[str] = None,
        original_client_sid: Optional[str] = None,
    ) -> None:
        """Handle a key request from another node."""
        pass

    @abstractmethod
    async def remove_keys_for_path(self, physical_path: str) -> int:
        """Remove all keys associated with the given physical path.

        This is useful when a system reconnects with new keys - we want to
        remove all old keys for that system before adding the new ones.

        Returns the number of keys removed.
        """
        pass

    @abstractmethod
    async def get_keys_for_path(self, physical_path: str) -> Iterable[dict[str, Any]]:
        """Get all keys associated with the given physical path.

        Args:
            physical_path: The physical path to get keys for.

        Returns:
            List of key dictionaries for the given path.
        """
        pass
