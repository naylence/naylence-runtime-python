"""
Factory for creating DefaultKeyManager instances.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.security.keys.key_store_factory import KeyStoreConfig

from .key_manager import KeyManager
from .key_manager_factory import KeyManagerConfig, KeyManagerFactory


class DefaultKeyManagerConfig(KeyManagerConfig):
    """Configuration for DefaultKeyManager."""

    type: str = "DefaultKeyManager"

    model_config = {"arbitrary_types_allowed": True}

    # Node context configuration
    has_upstream: bool = False
    node_id: Optional[str] = None

    # Optional overrides for advanced use cases
    key_store: Optional[KeyStoreConfig] = None


class DefaultKeyManagerFactory(KeyManagerFactory):
    """Factory for creating DefaultKeyManager instances."""

    type = "DefaultKeyManager"
    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultKeyManagerConfig | dict[str, Any]] = None,
        key_store: Optional[KeyStore] = None,
        **kwargs: Any,
    ) -> KeyManager:
        """Create a DefaultKeyManager instance."""
        # Lazy import to avoid circular dependencies
        from .default_key_manager import DefaultKeyManager

        # Use provided key_store or fall back to global singleton
        if key_store is None:
            from naylence.fame.security.keys.key_store import get_key_store

            key_store = get_key_store()

        # Use config or defaults
        if config is None:
            config = DefaultKeyManagerConfig()
        elif isinstance(config, dict):
            config = DefaultKeyManagerConfig(**config)

        return DefaultKeyManager(key_store=key_store)
