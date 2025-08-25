"""
In-memory key store plus its factory registration.
"""

from __future__ import annotations

from typing import Any, Optional

from .key_store import KeyStore
from .key_store_factory import KeyStoreConfig, KeyStoreFactory


class InMemoryKeyStoreConfig(KeyStoreConfig):
    type: str = "InMemoryKeyStore"
    initial_keys: dict[str, dict] | None = None


class InMemoryKeyStoreFactory(KeyStoreFactory):
    async def create(
        self,
        config: Optional[InMemoryKeyStoreConfig | dict[str, Any]] = None,
        **_: Any,
    ) -> KeyStore:
        from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore

        return InMemoryKeyStore()
