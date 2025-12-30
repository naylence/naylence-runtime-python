"""
Storage profile factory for predefined storage configurations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import Expressions, create_resource
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
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

# Storage provider factory base type constant
STORAGE_PROVIDER_FACTORY_BASE_TYPE = "StorageProviderFactory"

# Register built-in profiles
_profiles_registered = False

def _ensure_profiles_registered() -> None:
    """Ensure built-in storage profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="storage-profile-factory")
    register_profile(STORAGE_PROVIDER_FACTORY_BASE_TYPE, PROFILE_NAME_MEMORY, MEMORY_PROFILE, opts)
    register_profile(STORAGE_PROVIDER_FACTORY_BASE_TYPE, PROFILE_NAME_SQLITE, SQLITE_PROFILE, opts)
    register_profile(STORAGE_PROVIDER_FACTORY_BASE_TYPE, PROFILE_NAME_ENCRYPTED_SQLITE, ENCRYPTED_SQLITE_PROFILE, opts)
    _profiles_registered = True

_ensure_profiles_registered()

def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve storage profile by name."""
    _ensure_profiles_registered()

    profile = get_profile(STORAGE_PROVIDER_FACTORY_BASE_TYPE, profile_name)
    if profile is not None:
        return profile

    # Try to discover from entry points
    discover_profile(STORAGE_PROVIDER_FACTORY_BASE_TYPE, profile_name)

    profile = get_profile(STORAGE_PROVIDER_FACTORY_BASE_TYPE, profile_name)
    if profile is None:
        raise ValueError(f"Unknown storage profile: {profile_name}")

    return profile

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

        storage_config = _resolve_profile_config(profile)

        return await create_resource(StorageProviderFactory, storage_config)
