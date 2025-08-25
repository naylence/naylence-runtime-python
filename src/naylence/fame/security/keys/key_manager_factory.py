from typing import Any, Optional, TypeVar

from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
)
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.security.keys.key_store import KeyStore


class KeyManagerConfig(ResourceConfig):
    """Common config fields for all KeyManager implementations."""

    type: str = "KeyManager"


C = TypeVar("C", bound=KeyManagerConfig)


class KeyManagerFactory(ResourceFactory[KeyManager, C]):  # pragma: no cover
    """Abstract resource-factory for KeyManager objects (pluggable implementations)."""

    @classmethod
    async def create_key_manager(
        cls,
        cfg: C | dict[str, Any],
        key_store: Optional[KeyStore] = None,
        **kwargs,
    ) -> KeyManager:
        """Create a KeyManager instance based on the provided configuration."""
        if isinstance(cfg, KeyManagerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        key_manager = await create_default_resource(
            KeyManagerFactory, cfg_dict, key_store=key_store, **kwargs
        )
        assert key_manager is not None, "Failed to create KeyManager instance"
        return key_manager
