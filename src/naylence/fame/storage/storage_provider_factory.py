from typing import Any, Optional, TypeVar

from pydantic import ConfigDict, Field

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.storage.storage_provider import StorageProvider


class StorageProviderConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "StorageProvider"
    params: Optional[dict[str, Any]] = Field(default=None, description="Backend-specific kwargs")


C = TypeVar("C", bound=StorageProviderConfig)


class StorageProviderFactory(ResourceFactory[StorageProvider, C]):
    """Pluggable factory, mirrors existing RouteStoreFactory pattern."""

    ...
