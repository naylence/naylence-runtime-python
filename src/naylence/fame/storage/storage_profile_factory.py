"""
Storage profile factory for predefined storage configurations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import Expressions, create_resource
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.storage.storage_provider_factory import (
    StorageProviderConfig,
    StorageProviderFactory,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


ENV_VAR_STORAGE_DB_DIRECTORY = "FAME_STORAGE_DB_DIRECTORY"
ENV_VAR_STORAGE_MASTER_KEY = "FAME_STORAGE_MASTER_KEY"
ENV_VAR_STORAGE_ENCRYPTED = "FAME_STORAGE_ENCRYPTED"


PROFILE_NAME_MEMORY = "memory"
PROFILE_NAME_SQLITE = "sqlite"
PROFILE_NAME_ENCRYPTED_SQLITE = "encrypted-sqlite"


MEMORY_PROFILE = {
    "type": "InMemoryStorageProvider",
}

SQLITE_PROFILE = {
    "type": "SQLiteStorageProvider",
    "db_directory": Expressions.env(ENV_VAR_STORAGE_DB_DIRECTORY, default="./data/sqlite"),
    "is_encrypted": Expressions.env(ENV_VAR_STORAGE_ENCRYPTED, default="false"),
    "master_key": Expressions.env(ENV_VAR_STORAGE_MASTER_KEY, default=""),  # Empty default for optional key
    "is_cached": True,
}

# Development profile - uses in-memory storage for simplicity
DEVELOPMENT_PROFILE = {
    "type": "InMemoryStorageProvider",
}

# Encrypted SQLite profile - explicitly enables encryption
ENCRYPTED_SQLITE_PROFILE = {
    "type": "SQLiteStorageProvider",
    "db_directory": Expressions.env(ENV_VAR_STORAGE_DB_DIRECTORY, default="./data/sqlite"),
    "is_encrypted": "true",  # Always encrypted for this profile
    "master_key": Expressions.env(ENV_VAR_STORAGE_MASTER_KEY),  # Required for encrypted profile
    "is_cached": True,
}


class StorageProfileConfig(StorageProviderConfig):
    type: str = "StorageProfile"

    profile: Optional[str] = Field(default=None, description="Storage profile name")


class StorageProfileFactory(StorageProviderFactory):
    async def create(
        self,
        config: Optional[StorageProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> StorageProvider:
        if isinstance(config, dict):
            config = StorageProfileConfig(**config)
        elif config is None:
            config = StorageProfileConfig(profile=PROFILE_NAME_MEMORY)

        profile = config.profile or PROFILE_NAME_MEMORY

        logger.debug("enabling_storage_profile", profile=profile)  # type: ignore

        if profile == PROFILE_NAME_MEMORY:
            storage_config = MEMORY_PROFILE
        elif profile == PROFILE_NAME_SQLITE:
            storage_config = SQLITE_PROFILE
        elif profile == PROFILE_NAME_ENCRYPTED_SQLITE:
            storage_config = ENCRYPTED_SQLITE_PROFILE
        else:
            raise ValueError(f"Unknown storage profile: {profile}")

        return await create_resource(StorageProviderFactory, storage_config)
