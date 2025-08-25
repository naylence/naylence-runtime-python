"""Random load balancing strategy factory."""

from typing import Any, Optional

from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)

from .load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)


class RandomLoadBalancingStrategyConfig(LoadBalancingStrategyConfig):
    type: str = "RandomLoadBalancingStrategy"


class RandomLoadBalancingStrategyFactory(LoadBalancingStrategyFactory):
    type: str = "RandomLoadBalancingStrategy"

    async def create(
        self,
        config: Optional[LoadBalancingStrategyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> LoadBalancingStrategy:
        from .random_load_balancing_strategy import RandomLoadBalancingStrategy

        return RandomLoadBalancingStrategy()
