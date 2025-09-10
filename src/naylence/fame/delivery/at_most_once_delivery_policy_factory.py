from __future__ import annotations

from typing import Any, Optional

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.delivery_policy_factory import (
    DeliveryPolicyConfig,
    DeliveryPolicyFactory,
)


class AtMostOnceDeliveryPolicyConfig(DeliveryPolicyConfig):
    """Configuration for the at-most-once envelope tracker."""

    type: str = "AtMostOnceMessageDeliveryPolicy"


class AtMostOnceDeliveryPolicyFactory(DeliveryPolicyFactory):
    """Factory for creating AtMostOnceMessageDeliveryPolicy instances."""

    async def create(
        self,
        config: Optional[AtMostOnceDeliveryPolicyConfig | dict[str, Any]] = None,
        **kwargs,
    ) -> DeliveryPolicy:
        # Handle config dict conversion
        if config and isinstance(config, dict):
            config = AtMostOnceDeliveryPolicyConfig(**config)

        from naylence.fame.delivery.at_most_once_delivery_policy import (
            AtMostOnceDeliveryPolicy,
        )

        return AtMostOnceDeliveryPolicy()
