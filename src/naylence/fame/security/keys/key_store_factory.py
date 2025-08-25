from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.core import ResourceConfig, ResourceFactory, create_resource


from typing import Any, Optional, TypeVar


class KeyStoreConfig(ResourceConfig):
    """Base config shared by all KeyStore implementations (empty for now)."""

    type: str = "KeyStore"
    

C = TypeVar("C", bound=KeyStoreConfig)


class KeyStoreFactory(ResourceFactory[KeyStore, C]):  # pragma: no cover
    """Abstract ResourceFactory façade for dependency-injection."""

    @classmethod
    async def create_key_store(
        cls,
        cfg: C | dict[str, Any],
        storage_provider: Optional[StorageProvider] = None,
        **kwargs,
    ) -> KeyStore:
        return await create_resource(KeyStoreFactory, cfg, storage_provider=storage_provider, **kwargs)


