"""
Routing profile factory for predefined routing policy configurations.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
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

# Routing policy factory base type constant
ROUTING_POLICY_FACTORY_BASE_TYPE = "RoutingPolicyFactory"

# Register built-in profiles
_profiles_registered = False

def _ensure_profiles_registered() -> None:
    """Ensure built-in routing profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="routing-profile-factory")
    register_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_DEVELOPMENT, DEVELOPMENT_PROFILE, opts)
    register_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_PRODUCTION, PRODUCTION_PROFILE, opts)
    register_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_BASIC, BASIC_PROFILE, opts)
    register_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_CAPABILITY_AWARE, CAPABILITY_AWARE_PROFILE, opts)
    register_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_HYBRID_ONLY, HYBRID_ONLY_PROFILE, opts)
    _profiles_registered = True

_ensure_profiles_registered()

def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve routing profile by name."""
    _ensure_profiles_registered()

    profile = get_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, profile_name)
    if profile is not None:
        return profile

    # Try to discover from entry points
    discover_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, profile_name)

    profile = get_profile(ROUTING_POLICY_FACTORY_BASE_TYPE, profile_name)
    if profile is None:
        raise ValueError(f"Unknown routing profile: {profile_name}")

    return profile

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

        routing_config = _resolve_profile_config(profile)

        return await create_resource(RoutingPolicyFactory, routing_config, **kwargs)
