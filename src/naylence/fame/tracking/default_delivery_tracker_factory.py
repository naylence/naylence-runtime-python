"""
Factory implementation for the default envelope tracker.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.tracking.delivery_tracker import (
    DeliveryTracker,
    DeliveryTrackerEventHandler,
    RetryEventHandler,
)
from naylence.fame.tracking.delivery_tracker_factory import (
    DeliveryTrackerConfig,
    DeliveryTrackerFactory,
)


class DefaultDeliveryTrackerConfig(DeliveryTrackerConfig):
    """Configuration for the default envelope tracker."""

    type: str = "DefaultDeliveryTracker"
    namespace: str = "default_delivery_tracker"


class DefaultDeliveryTrackerFactory(DeliveryTrackerFactory):
    """Factory for creating DefaultDeliveryTracker instances."""

    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultDeliveryTrackerConfig | dict[str, Any]] = None,
        storage_provider: Optional[StorageProvider] = None,
        kv_store: Optional[KeyValueStore] = None,
        event_handler: Optional[DeliveryTrackerEventHandler] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        **kwargs,
    ) -> DeliveryTracker:
        from naylence.fame.storage.in_memory_storage_provider import (
            InMemoryStorageProvider,
        )
        from naylence.fame.tracking.default_delivery_tracker import (
            DefaultDeliveryTracker,
        )
        from naylence.fame.tracking.delivery_tracker import TrackedEnvelope

        # Handle config dict conversion
        if config and isinstance(config, dict):
            config = DefaultDeliveryTrackerConfig(**config)

        # Determine the KV store to use
        kv: KeyValueStore[TrackedEnvelope]
        if kv_store:
            kv = kv_store
        elif storage_provider:
            kv = await storage_provider.get_kv_store(
                model_cls=TrackedEnvelope,
                namespace="delivery_tracker",
            )
        else:
            # Default to in-memory provider
            in_memory_provider = InMemoryStorageProvider()
            kv = await in_memory_provider.get_kv_store(
                model_cls=TrackedEnvelope,
                namespace="delivery_tracker",
            )

        tracker = DefaultDeliveryTracker(
            kv_store=kv,
            retry_handler=retry_handler,
        )

        # Add event handler if provided
        if event_handler:
            tracker.add_event_handler(event_handler)

        return tracker
