from __future__ import annotations

from typing import Any, Optional

from naylence.fame.core import (
    create_resource,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
    RoutingPolicyConfig,
    RoutingPolicyFactory,
)
from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class CapabilityAwareRoutingPolicyConfig(RoutingPolicyConfig):
    type: str = "CapabilityAwareRoutingPolicy"

    load_balancing_strategy: Optional[LoadBalancingStrategyConfig] = None


class CapabilityAwareRoutingPolicyFactory(RoutingPolicyFactory):
    async def create(
        self,
        config: Optional[CapabilityAwareRoutingPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> RoutingPolicy:
        from naylence.fame.sentinel.capability_aware_routing_policy import (
            CapabilityAwareRoutingPolicy,
        )

        assert config
        lbs_config = getattr(config, "load_balancing_strategy", None)
        if lbs_config is None and isinstance(config, dict):
            lbs_config = config.get("load_balancing_strategy")
        load_balancing_strategy = await create_resource(LoadBalancingStrategyFactory, lbs_config)
        return CapabilityAwareRoutingPolicy(load_balancing_strategy)
