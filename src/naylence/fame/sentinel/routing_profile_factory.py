"""
Routing profile factory for predefined routing policy configurations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
    RoutingPolicyConfig,
    RoutingPolicyFactory,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


# Routing Profile Names
PROFILE_NAME_DEVELOPMENT = "development"
PROFILE_NAME_PRODUCTION = "production"
PROFILE_NAME_BASIC = "basic"
PROFILE_NAME_CAPABILITY_AWARE = "capability-aware"
PROFILE_NAME_HYBRID_ONLY = "hybrid-only"


# Development profile - simple hybrid routing with HRW load balancing
DEVELOPMENT_PROFILE = {
    "type": "CompositeRoutingPolicy",
    "policies": [
        {
            "type": "HybridPathRoutingPolicy",
            "load_balancing_strategy": {"type": "HRWLoadBalancingStrategy"},
        }
    ],
}

# Production profile - capability-aware + hybrid routing (stickiness handled dynamically)
PRODUCTION_PROFILE = {
    "type": "CompositeRoutingPolicy",
    "policies": [
        {"type": "CapabilityAwareRoutingPolicy"},
        {
            "type": "HybridPathRoutingPolicy",
            "load_balancing_strategy": {"type": "HRWLoadBalancingStrategy"},
        },
    ],
}

# Basic profile - alias for development (simple hybrid routing)
BASIC_PROFILE = DEVELOPMENT_PROFILE

# Capability-aware profile - capability routing only
CAPABILITY_AWARE_PROFILE = {"type": "CapabilityAwareRoutingPolicy"}

# Hybrid-only profile - hybrid routing with HRW load balancing
HYBRID_ONLY_PROFILE = {
    "type": "HybridPathRoutingPolicy",
    "load_balancing_strategy": {"type": "HRWLoadBalancingStrategy"},
}


class RoutingProfileConfig(RoutingPolicyConfig):
    type: str = "RoutingProfile"

    profile: Optional[str] = Field(default=None, description="Routing profile name")


class RoutingProfileFactory(RoutingPolicyFactory):
    async def create(
        self,
        config: Optional[RoutingProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> RoutingPolicy:
        if isinstance(config, dict):
            config = RoutingProfileConfig(**config)
        elif config is None:
            config = RoutingProfileConfig(profile=PROFILE_NAME_DEVELOPMENT)

        profile = config.profile or PROFILE_NAME_DEVELOPMENT

        logger.debug("enabling_routing_profile", profile=profile)  # type: ignore

        if profile == PROFILE_NAME_DEVELOPMENT:
            routing_config = DEVELOPMENT_PROFILE
        elif profile == PROFILE_NAME_PRODUCTION:
            routing_config = PRODUCTION_PROFILE
        elif profile == PROFILE_NAME_BASIC:
            routing_config = BASIC_PROFILE
        elif profile == PROFILE_NAME_CAPABILITY_AWARE:
            routing_config = CAPABILITY_AWARE_PROFILE
        elif profile == PROFILE_NAME_HYBRID_ONLY:
            routing_config = HYBRID_ONLY_PROFILE
        else:
            raise ValueError(f"Unknown routing profile: {profile}")

        return await create_resource(RoutingPolicyFactory, routing_config, **kwargs)
