"""Load balancing strategy factory base class."""

from typing import TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource

from .load_balancing_strategy import LoadBalancingStrategy


class LoadBalancingStrategyConfig(ResourceConfig):
    type: str = "LoadBalancingStrategy"


C = TypeVar("C", bound=LoadBalancingStrategyConfig)


class LoadBalancingStrategyFactory(ResourceFactory[LoadBalancingStrategy, C]):
    @staticmethod
    async def create_load_balancing_strategy() -> LoadBalancingStrategy:
        from naylence.fame.sentinel.load_balancing.hrw_load_balancing_strategy_factory import (
            HRWLoadBalancingStrategyConfig,
        )

        load_balancing_strategy = await create_resource(
            LoadBalancingStrategyFactory, HRWLoadBalancingStrategyConfig()
        )

        return load_balancing_strategy
