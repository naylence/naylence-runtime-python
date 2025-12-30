"""
Load balancing profile factory for predefined load balancing configurations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
from naylence.fame.util.logging import getLogger

from .load_balancing_strategy import LoadBalancingStrategy
from .load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)

logger = getLogger(__name__)


PROFILE_NAME_RANDOM = "random"
PROFILE_NAME_ROUND_ROBIN = "round_robin"
PROFILE_NAME_HRW = "hrw"
PROFILE_NAME_STICKY_HRW = "sticky-hrw"
PROFILE_NAME_DEVELOPMENT = "development"


RANDOM_PROFILE = {
    "type": "RandomLoadBalancingStrategy",
}

ROUND_ROBIN_PROFILE = {
    "type": "RoundRobinLoadBalancingStrategy",
}

HRW_PROFILE = {
    "type": "HRWLoadBalancingStrategy",
}

STICKY_HRW_PROFILE = {
    "type": "HRWLoadBalancingStrategy",
    "sticky_attribute": "session_id",
}

# Development profile - uses round robin for predictable behavior
DEVELOPMENT_PROFILE = {
    "type": "RoundRobinLoadBalancingStrategy",
}

# Load balancing strategy factory base type constant
LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE = "LoadBalancingStrategyFactory"

# Register built-in profiles
_profiles_registered = False


def _ensure_profiles_registered() -> None:
    """Ensure built-in load balancing profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="load-balancing-profile-factory")
    register_profile(LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, PROFILE_NAME_RANDOM, RANDOM_PROFILE, opts)
    register_profile(
        LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, PROFILE_NAME_ROUND_ROBIN, ROUND_ROBIN_PROFILE, opts
    )
    register_profile(LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, PROFILE_NAME_HRW, HRW_PROFILE, opts)
    register_profile(
        LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, PROFILE_NAME_STICKY_HRW, STICKY_HRW_PROFILE, opts
    )
    register_profile(
        LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, PROFILE_NAME_DEVELOPMENT, DEVELOPMENT_PROFILE, opts
    )
    _profiles_registered = True


_ensure_profiles_registered()


def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve load balancing profile by name."""
    _ensure_profiles_registered()

    profile = get_profile(LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, profile_name)
    if profile is not None:
        return profile

    # Try to discover from entry points
    discover_profile(LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, profile_name)

    profile = get_profile(LOAD_BALANCING_STRATEGY_FACTORY_BASE_TYPE, profile_name)
    if profile is None:
        raise ValueError(f"Unknown load balancing profile: {profile_name}")

    return profile


class LoadBalancingProfileConfig(LoadBalancingStrategyConfig):
    type: str = "LoadBalancingProfile"

    profile: Optional[str] = Field(default=None, description="Load balancing profile name")


class LoadBalancingProfileFactory(LoadBalancingStrategyFactory):
    type: str = "LoadBalancingProfile"

    async def create(
        self,
        config: Optional[LoadBalancingProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> LoadBalancingStrategy:
        if isinstance(config, dict):
            config = LoadBalancingProfileConfig(**config)
        elif config is None:
            config = LoadBalancingProfileConfig(profile=PROFILE_NAME_DEVELOPMENT)

        profile = config.profile or PROFILE_NAME_DEVELOPMENT

        logger.debug("enabling_load_balancing_profile", profile=profile)

        lb_config = _resolve_profile_config(profile)

        return await create_resource(LoadBalancingStrategyFactory, lb_config, **kwargs)
