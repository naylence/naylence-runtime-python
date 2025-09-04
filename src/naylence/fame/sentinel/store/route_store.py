from __future__ import annotations

from datetime import datetime
from typing import Any, List, Mapping, Optional

from pydantic import BaseModel, Field

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.key_value_store import KeyValueStore


class RouteEntry(BaseModel):
    system_id: str
    assigned_path: str
    instance_id: str
    connector_config: Optional[ConnectorConfig] = Field(default=None)
    durable: bool = Field(
        default=False,
        description="Mirrors connector config.durable; if true, skip auto-expiration.",
    )

    attach_expires_at: Optional[datetime] = Field(
        default=None, description="When this fame route should be auto-expired"
    )

    metadata: Optional[Mapping[str, Any]] = Field(
        default=None,
        description="Arbitrary extra metadata (e.g. capabilities, source info)",
    )

    callback_grants: Optional[List[dict[str, Any]]] = Field(
        default=None,
        description="List of inbound connector grants the child supports for reverse connections",
    )


RouteStore = KeyValueStore[RouteEntry]

_instance: Optional[RouteStore] = None


def get_default_route_store() -> RouteStore:
    global _instance
    if _instance is None:
        _instance = InMemoryKVStore(RouteEntry)
    return _instance
