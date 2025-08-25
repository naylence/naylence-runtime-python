"""HRW load balancing strategy factory."""

from typing import Any, Optional

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)

from .load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)


class HRWLoadBalancingStrategyConfig(LoadBalancingStrategyConfig):
    type: str = "HRWLoadBalancingStrategy"
    sticky_attribute: Optional[str] = None


class HRWLoadBalancingStrategyFactory(LoadBalancingStrategyFactory):
    type: str = "HRWLoadBalancingStrategy"

    async def create(
        self,
        config: Optional[HRWLoadBalancingStrategyConfig | dict[str, Any]] = None,
        key_provider: Optional[KeyProvider] = None,
        **kwargs: Any,
    ) -> LoadBalancingStrategy:
        from .hrw_load_balancing_strategy import HRWLoadBalancingStrategy

        if isinstance(config, dict):
            config = HRWLoadBalancingStrategyConfig(**config)

        # TODO: sticky_attribute vs stickiness
        sticky_attribute = None
        if config:
            sticky_attribute = config.sticky_attribute

        return HRWLoadBalancingStrategy(sticky_attr=sticky_attribute)
