from __future__ import annotations

from typing import Any, Optional

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.delivery_policy_factory import (
    DeliveryPolicyConfig,
    DeliveryPolicyFactory,
)
from naylence.fame.delivery.retry_policy import RetryPolicy


class AtLeastOnceDeliveryPolicyConfig(DeliveryPolicyConfig):
    """Configuration for the at-least-once delivery policy."""

    type: str = "AtLeastOnceDeliveryPolicy"
    sender_retry_policy: Optional[RetryPolicy] = None
    receiver_retry_policy: Optional[RetryPolicy] = None


class AtLeastOnceDeliveryPolicyFactory(DeliveryPolicyFactory):
    """Factory for creating AtLeastOnceDeliveryPolicy instances."""

    is_default: bool = True

    async def create(
        self,
        config: Optional[AtLeastOnceDeliveryPolicyConfig | dict[str, Any]] = None,
        **kwargs,
    ) -> DeliveryPolicy:
        if isinstance(config, dict):
            config = AtLeastOnceDeliveryPolicyConfig(**config)

        from naylence.fame.delivery.at_least_once_delivery_policy import (
            AtLeastOnceDeliveryPolicy,
        )

        return AtLeastOnceDeliveryPolicy(
            sender_retry_policy=config.sender_retry_policy if config else None,
            receiver_retry_policy=config.receiver_retry_policy if config else None,
        )
