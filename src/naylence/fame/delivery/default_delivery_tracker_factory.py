"""
Factory implementation for the default envelope tracker.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.delivery.delivery_tracker import (
    DeliveryTracker,
    DeliveryTrackerEventHandler,
)
from naylence.fame.delivery.delivery_tracker_factory import (
    DeliveryTrackerConfig,
    DeliveryTrackerFactory,
)
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.storage.storage_provider import StorageProvider


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
        tracker_store: Optional[KeyValueStore] = None,
        event_handler: Optional[DeliveryTrackerEventHandler] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        **kwargs,
    ) -> DeliveryTracker:
        from naylence.fame.delivery.default_delivery_tracker import (
            DefaultDeliveryTracker,
        )
        from naylence.fame.delivery.delivery_tracker import TrackedEnvelope
        from naylence.fame.storage.in_memory_storage_provider import (
            InMemoryStorageProvider,
        )

        # Handle config dict conversion
        if config and isinstance(config, dict):
            config = DefaultDeliveryTrackerConfig(**config)

        # Determine the KV store to use
        # tracker_store: KeyValueStore[TrackedEnvelope]
        if tracker_store:
            pass
        elif storage_provider:
            tracker_store = await storage_provider.get_kv_store(
                model_cls=TrackedEnvelope,
                namespace="__delivery_tracker",
            )
        else:
            # Default to in-memory provider
            in_memory_provider = InMemoryStorageProvider()
            tracker_store = await in_memory_provider.get_kv_store(
                model_cls=TrackedEnvelope,
                namespace="__delivery_tracker",
            )

        tracker = DefaultDeliveryTracker(tracker_store=tracker_store)

        # Add event handler if provided
        if event_handler:
            tracker.add_event_handler(event_handler)

        return tracker
