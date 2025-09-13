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
        event_handler: Optional[DeliveryTrackerEventHandler] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        **kwargs,
    ) -> DeliveryTracker:
        from naylence.fame.delivery.default_delivery_tracker import (
            DefaultDeliveryTracker,
        )
        from naylence.fame.storage.in_memory_storage_provider import (
            InMemoryStorageProvider,
        )

        # Handle config dict conversion
        if config and isinstance(config, dict):
            config = DefaultDeliveryTrackerConfig(**config)

        if storage_provider is None:
            storage_provider = InMemoryStorageProvider()

        tracker = DefaultDeliveryTracker(storage_provider, **kwargs)

        # Add event handler if provided
        if event_handler:
            tracker.add_event_handler(event_handler)

        return tracker
