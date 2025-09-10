"""
Factory for envelope tracker implementations following Fame's ResourceFactory pattern.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.delivery.delivery_tracker import (
    DeliveryTracker,
    DeliveryTrackerEventHandler,
)
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.storage.storage_provider import StorageProvider


class DeliveryTrackerConfig(ResourceConfig):
    """Base configuration for envelope trackers."""

    type: str = "DeliveryTracker"
    namespace: str = "delivery_tracker"


C = TypeVar("C", bound=DeliveryTrackerConfig)


class DeliveryTrackerFactory(ResourceFactory[DeliveryTracker, C]):
    """Abstract factory for creating envelope tracker instances."""

    @classmethod
    async def create_delivery_tracker(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        storage_provider: Optional[StorageProvider] = None,
        tracker_store: Optional[KeyValueStore] = None,
        event_handler: Optional[DeliveryTrackerEventHandler] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        **kwargs,
    ) -> Optional[DeliveryTracker]:
        """Create an envelope tracker instance based on the provided configuration."""

        return await create_resource(
            DeliveryTrackerFactory,
            cfg,
            storage_provider=storage_provider,
            kv_store=tracker_store,
            event_handler=event_handler,
            retry_handler=retry_handler,
            **kwargs,
        )
