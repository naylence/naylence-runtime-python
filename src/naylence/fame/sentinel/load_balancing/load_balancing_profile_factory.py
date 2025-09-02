"""
Load balancing profile factory for predefined load balancing configurations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
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

        if profile == PROFILE_NAME_RANDOM:
            lb_config = RANDOM_PROFILE
        elif profile == PROFILE_NAME_ROUND_ROBIN:
            lb_config = ROUND_ROBIN_PROFILE
        elif profile == PROFILE_NAME_HRW:
            lb_config = HRW_PROFILE
        elif profile == PROFILE_NAME_STICKY_HRW:
            lb_config = STICKY_HRW_PROFILE
        elif profile == PROFILE_NAME_DEVELOPMENT:
            lb_config = DEVELOPMENT_PROFILE
        else:
            raise ValueError(f"Unknown load balancing profile: {profile}")

        return await create_resource(LoadBalancingStrategyFactory, lb_config, **kwargs)
