"""Sticky load balancing strategy factory."""

from typing import Any, Optional

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.stickiness.load_balancer_stickiness_manager import (
    LoadBalancerStickinessManager,
)

from .load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)


class StickyLoadBalancingStrategyConfig(LoadBalancingStrategyConfig):
    type: str = "StickyLoadBalancingStrategy"


class StickyLoadBalancingStrategyFactory(LoadBalancingStrategyFactory):
    type: str = "StickyLoadBalancingStrategy"

    async def create(
        self,
        config: Optional[StickyLoadBalancingStrategyConfig | dict[str, Any]] = None,
        *,
        stickiness_manager: Optional[LoadBalancerStickinessManager] = None,
        key_provider: Optional[KeyProvider] = None,
        **kwargs: Any,
    ):
        from .sticky_load_balancing_strategy import StickyLoadBalancingStrategy

        if not config:
            raise ValueError("StickyLoadBalancingStrategy requires configuration")
        elif isinstance(config, dict):
            config = StickyLoadBalancingStrategyConfig(**config)

        # Use provided stickiness_manager or create new one
        assert stickiness_manager

        return StickyLoadBalancingStrategy(stickiness_manager)
