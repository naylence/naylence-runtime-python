from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.storage.storage_provider_factory import (
    StorageProviderConfig,
    StorageProviderFactory,
)


class InMemoryStorageProviderConfig(StorageProviderConfig):
    type: str = "InMemoryStorageProvider"


class InMemoryStorageProviderFactory(StorageProviderFactory):
    async def create(
        self,
        config: InMemoryStorageProviderConfig | dict | None = None,
        **kwargs,
    ) -> StorageProvider:
        from naylence.fame.storage.in_memory_storage_provider import (
            InMemoryStorageProvider,
        )

        return InMemoryStorageProvider()
