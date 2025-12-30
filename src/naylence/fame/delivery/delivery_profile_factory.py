from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.delivery_policy_factory import DeliveryPolicyConfig, DeliveryPolicyFactory
from naylence.fame.factory import Expressions, create_resource
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
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

# Delivery policy factory base type constant
DELIVERY_POLICY_FACTORY_BASE_TYPE = "DeliveryPolicyFactory"

# Register built-in profiles
_profiles_registered = False


def _ensure_profiles_registered() -> None:
    """Ensure built-in delivery profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="delivery-profile-factory")
    register_profile(
        DELIVERY_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_AT_LEAST_ONCE, AT_LEAST_ONCE_PROFILE, opts
    )
    register_profile(
        DELIVERY_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_AT_MOST_ONCE, AT_MOST_ONCE_PROFILE, opts
    )
    _profiles_registered = True


_ensure_profiles_registered()


def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve delivery profile by name."""
    _ensure_profiles_registered()

    profile = get_profile(DELIVERY_POLICY_FACTORY_BASE_TYPE, profile_name)
    if profile is not None:
        return profile

    # Try to discover from entry points
    discover_profile(DELIVERY_POLICY_FACTORY_BASE_TYPE, profile_name)

    profile = get_profile(DELIVERY_POLICY_FACTORY_BASE_TYPE, profile_name)
    if profile is None:
        raise ValueError(f"Unknown delivery profile: {profile_name}")

    return profile


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
        delivery_policy_config = _resolve_profile_config(profile)

        logger.debug("enabling_delivery_profile", profile=profile)  # type: ignore

        return await create_resource(DeliveryPolicyFactory, delivery_policy_config)
