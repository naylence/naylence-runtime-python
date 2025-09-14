"""
SQLite storage provider configuration and factory.

This module provides the configuration and factory for creating SQLite storage providers
with optional encryption support using the credential provider pattern for master keys.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    CredentialProviderFactory,
)
from naylence.fame.security.credential.secret_source import SecretSource
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.storage.storage_provider_factory import (
    StorageProviderConfig,
    StorageProviderFactory,
)


class SQLiteStorageProviderConfig(StorageProviderConfig):
    """Configuration for SQLite storage provider."""

    type: str = "SQLiteStorageProvider"

    db_directory: str = Field(
        default="./data/sqlite",
        description="Directory where SQLite database files will be stored",
    )

    is_encrypted: bool = Field(default=False, description="Whether to encrypt stored data")

    is_cached: bool = Field(
        default=True,
        description="Whether to enable in-memory caching values",
    )

    master_key: Optional[Annotated[CredentialProviderConfig, SecretSource]] = Field(
        default=None,
        description="Master encryption key from various sources (plain text, env://VAR, secret://name, "
        "or provider config). Required when is_encrypted=True",
    )


class SQLiteStorageProviderFactory(StorageProviderFactory):
    """Factory for creating SQLite storage providers."""

    async def create(
        self,
        config: Optional[SQLiteStorageProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> StorageProvider:
        """
        Create a SQLite storage provider instance.

        Args:
            config: SQLite storage provider configuration
            **kwargs: Additional keyword arguments

        Returns:
            Configured SQLite storage provider instance

        Raises:
            ValueError: If configuration is invalid
        """
        if not config or not isinstance(config, SQLiteStorageProviderConfig):
            raise ValueError("SQLiteStorageProviderConfig is required")

        master_key_provider: Optional[CredentialProvider] = None

        # If encryption is enabled, we need a master key provider
        if config.is_encrypted:
            if not config.master_key:
                raise ValueError("master_key is required when is_encrypted=True")

            # Create the credential provider for the master key
            master_key_provider = await create_resource(CredentialProviderFactory, config.master_key)
        elif config.master_key:
            # Warn if master_key is provided but encryption is disabled
            import warnings

            warnings.warn(
                "master_key is provided but is_encrypted=False. The master key will be ignored.",
                UserWarning,
            )

        # Import the actual provider class
        from naylence.fame.storage.sqlite_storage_provider import SQLiteStorageProvider

        return SQLiteStorageProvider(
            db_directory=config.db_directory,
            is_encrypted=config.is_encrypted,
            master_key_provider=master_key_provider,
            is_cached=config.is_cached,
        )
