"""
Factory for StorageBackedKeyStore with lazy importing.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.keys.key_store import (
    KeyStore,
)
from naylence.fame.security.keys.key_store_factory import (
    KeyStoreConfig,
    KeyStoreFactory,
)
from naylence.fame.storage.storage_provider import StorageProvider


class StorageBackedKeyStoreConfig(KeyStoreConfig):
    """Configuration for StorageBackedKeyStore."""

    type: str = "StorageBackedKeyStore"
    namespace: str = "keystore"  # Default namespace for key-value storage


class StorageBackedKeyStoreFactory(KeyStoreFactory):
    """Factory for creating StorageBackedKeyStore instances with lazy import."""

    async def create(
        self,
        config: Optional[StorageBackedKeyStoreConfig | dict[str, Any]] = None,
        storage_provider: Optional[StorageProvider] = None,
        **kwargs: Any,
    ) -> KeyStore:
        if storage_provider is None:
            raise ValueError("StorageBackedKeyStore requires a storage_provider")

        # Lazy import to avoid circular dependencies
        from .storage_backed_keystore import StorageBackedKeyStore

        # Extract configuration
        if isinstance(config, dict):
            namespace = config.get("namespace", "keystore")
        elif config is not None:
            namespace = config.namespace
        else:
            namespace = "keystore"

        return await StorageBackedKeyStore.create(storage_provider, namespace=namespace)
