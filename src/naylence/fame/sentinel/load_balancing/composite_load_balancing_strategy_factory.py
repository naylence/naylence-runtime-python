"""Composite load balancing strategy factory."""

from typing import Any, Optional

from naylence.fame.factory import create_resource

from .load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)


class CompositeLoadBalancingStrategyConfig(LoadBalancingStrategyConfig):
    type: str = "CompositeLoadBalancingStrategy"
    strategies: list[LoadBalancingStrategyConfig]


class CompositeLoadBalancingStrategyFactory(LoadBalancingStrategyFactory):
    type: str = "CompositeLoadBalancingStrategy"

    async def create(
        self,
        config: Optional[CompositeLoadBalancingStrategyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ):
        from .composite_load_balancing_strategy import CompositeLoadBalancingStrategy

        strategies_list = None
        if not config:
            raise ValueError("CompositeLoadBalancingStrategy requires at least one strategy configuration")
        if isinstance(config, dict):
            strategies_list = config.get("strategies")
        else:
            strategies_list = getattr(config, "strategies", None)
        if not strategies_list:
            raise ValueError("CompositeLoadBalancingStrategy requires at least one strategy configuration")

        strategies = []
        for strategy_config in strategies_list:
            # Use polymorphic resource creation for each strategy
            strategy = await create_resource(LoadBalancingStrategyFactory, strategy_config, **kwargs)
            strategies.append(strategy)

        return CompositeLoadBalancingStrategy(strategies)
