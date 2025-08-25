"""Round robin load balancing strategy factory."""

from typing import Any, Optional

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)

from .load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)


class RoundRobinLoadBalancingStrategyConfig(LoadBalancingStrategyConfig):
    type: str = "RoundRobinLoadBalancingStrategy"


class RoundRobinLoadBalancingStrategyFactory(LoadBalancingStrategyFactory):
    type: str = "RoundRobinLoadBalancingStrategy"

    async def create(
        self,
        config: Optional[RoundRobinLoadBalancingStrategyConfig | dict[str, Any]] = None,
        key_provider: Optional[KeyProvider] = None,
        **kwargs: Any,
    ) -> LoadBalancingStrategy:
        from .round_robin_load_balancing_strategy import RoundRobinLoadBalancingStrategy

        return RoundRobinLoadBalancingStrategy()
