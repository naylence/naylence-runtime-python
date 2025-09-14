from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.delivery_policy_factory import DeliveryPolicyConfig, DeliveryPolicyFactory
from naylence.fame.factory import Expressions, create_resource
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


PROFILE_NAME_AT_LEAST_ONCE = "at-least-once"
PROFILE_NAME_AT_MOST_ONCE = "at-most-once"


ENV_VAR_FAME_DELIVERY_MAX_RETRIES = "FAME_DELIVERY_MAX_RETRIES"
ENV_VAR_FAME_DELIVERY_BASE_DELAY_MS = "FAME_DELIVERY_BASE_DELAY_MS"
ENV_VAR_FAME_DELIVERY_MAX_DELAY_MS = "FAME_DELIVERY_MAX_DELAY_MS"
ENV_VAR_FAME_DELIVERY_JITTER_MS = "FAME_DELIVERY_JITTER_MS"
ENV_VAR_FAME_DELIVERY_BACKOFF_FACTOR = "FAME_DELIVERY_BACKOFF_FACTOR"

AT_LEAST_ONCE_PROFILE = {
    "type": "AtLeastOnceDeliveryPolicy",
    "sender_retry_policy": {
        "max_retries": Expressions.env(ENV_VAR_FAME_DELIVERY_MAX_RETRIES, "5"),
        "base_delay_ms": Expressions.env(ENV_VAR_FAME_DELIVERY_BASE_DELAY_MS, "1000"),
        "max_delay_ms": Expressions.env(ENV_VAR_FAME_DELIVERY_MAX_DELAY_MS, "10000"),
        "jitter_ms": Expressions.env(ENV_VAR_FAME_DELIVERY_JITTER_MS, "200"),
        "backoff_factor": Expressions.env(ENV_VAR_FAME_DELIVERY_BACKOFF_FACTOR, "2.0"),
    },
    "receiver_retry_policy": {
        "max_retries": Expressions.env(ENV_VAR_FAME_DELIVERY_MAX_RETRIES, "6"),
        "base_delay_ms": Expressions.env(ENV_VAR_FAME_DELIVERY_BASE_DELAY_MS, "100"),
        "max_delay_ms": Expressions.env(ENV_VAR_FAME_DELIVERY_MAX_DELAY_MS, "2000"),
        "jitter_ms": Expressions.env(ENV_VAR_FAME_DELIVERY_JITTER_MS, "50"),
        "backoff_factor": Expressions.env(ENV_VAR_FAME_DELIVERY_BACKOFF_FACTOR, "1.8"),
    },
}

AT_MOST_ONCE_PROFILE = {"type": "AtMostOnceDeliveryPolicy"}


class DeliveryProfileConfig(DeliveryPolicyConfig):
    type: str = "DeliveryProfile"

    profile: Optional[str] = Field(default=None, description="Delivery profile name")


class DeliveryProfileFactory(DeliveryPolicyFactory):
    async def create(
        self,
        config: Optional[DeliveryProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> DeliveryPolicy:
        if isinstance(config, dict):
            config = DeliveryProfileConfig(**config)
        elif config is None:
            config = DeliveryProfileConfig(profile=PROFILE_NAME_AT_LEAST_ONCE)

        profile = config.profile

        if profile == PROFILE_NAME_AT_LEAST_ONCE:
            from naylence.fame.delivery.at_least_once_delivery_policy_factory import (
                AtLeastOnceDeliveryPolicyConfig,
            )

            delivery_policy_config = AtLeastOnceDeliveryPolicyConfig(**AT_LEAST_ONCE_PROFILE)
        elif profile == PROFILE_NAME_AT_MOST_ONCE:
            from naylence.fame.delivery.at_most_once_delivery_policy_factory import (
                AtMostOnceDeliveryPolicyConfig,
            )

            delivery_policy_config = AtMostOnceDeliveryPolicyConfig(**AT_MOST_ONCE_PROFILE)

        else:
            raise ValueError(f"Unknown delivery profile: {profile}")

        logger.debug("enabling_delivery_profile", profile=profile)  # type: ignore

        return await create_resource(DeliveryPolicyFactory, delivery_policy_config)
