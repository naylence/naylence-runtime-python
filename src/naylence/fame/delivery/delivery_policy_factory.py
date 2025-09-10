from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.retry_event_handler import (
    RetryEventHandler,
)
from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource


class DeliveryPolicyConfig(ResourceConfig):
    type: str = "MessageDeliveryPolicy"


C = TypeVar("C", bound=DeliveryPolicyConfig)


class DeliveryPolicyFactory(ResourceFactory[DeliveryPolicy, C]):
    """Abstract factory for creating message delivery policy instances."""

    @classmethod
    async def create_delivery_policy(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        **kwargs,
    ) -> Optional[DeliveryPolicy]:
        """Create an envelope tracker instance based on the provided configuration."""

        return await create_resource(
            DeliveryPolicyFactory,
            cfg,
            retry_handler=retry_handler,
            **kwargs,
        )
