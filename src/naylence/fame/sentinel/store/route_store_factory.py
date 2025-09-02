from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import Field

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.sentinel.store.route_store import RouteEntry, RouteStore
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


class RouteStoreConfig(ResourceConfig):
    type: str = "RouteStore"
    params: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Implementation-specific parameters (e.g. Redis URL)",
    )


class RouteStoreFactory(ResourceFactory[RouteStore, RouteStoreConfig]): ...


class InMemoryRouteStoreFactory(RouteStoreFactory):
    async def create(
        self, config: Optional[RouteStoreConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> RouteStore:
        # 'none' store: no-op implementation
        if not config:
            raise ValueError("Config not set")

        return InMemoryKVStore(RouteEntry)
