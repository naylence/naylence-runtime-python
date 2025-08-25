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
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class HybridPathRoutingPolicyConfig(RoutingPolicyConfig):
    type: str = "HybridPathRoutingPolicy"
    load_balancing_strategy: Optional[LoadBalancingStrategyConfig] = None


class HybridPathRoutingPolicyFactory(RoutingPolicyFactory):
    async def create(
        self,
        config: Optional[HybridPathRoutingPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> RoutingPolicy:
        assert config
        from naylence.fame.sentinel.hybrid_path_routing_policy import (
            HybridPathRoutingPolicy,
        )

        if isinstance(config, dict):
            lb_config = config.get("load_balancing_strategy")
        else:
            lb_config = config.load_balancing_strategy
        load_balancing_strategy = await create_resource(LoadBalancingStrategyFactory, lb_config)
        return HybridPathRoutingPolicy(load_balancing_strategy)
