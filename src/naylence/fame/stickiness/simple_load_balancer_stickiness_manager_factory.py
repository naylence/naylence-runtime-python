from __future__ import annotations

from typing import Any, Optional

from .load_balancer_stickiness_manager import LoadBalancerStickinessManager
from .load_balancer_stickiness_manager_factory import (
    LoadBalancerStickinessManagerConfig,
    LoadBalancerStickinessManagerFactory,
)


class SimpleLoadBalanderStickinessManagerConfig(LoadBalancerStickinessManagerConfig):
    type: str = "SimpleLoadBalancerStickinessManager"


class SimpleLoadBalancerStickinessManagerFactory(LoadBalancerStickinessManagerFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[SimpleLoadBalanderStickinessManagerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> LoadBalancerStickinessManager:
        cfg: Optional[SimpleLoadBalanderStickinessManagerConfig] = None
        if isinstance(config, LoadBalancerStickinessManagerConfig):
            cfg = config
        elif isinstance(config, dict):
            cfg = SimpleLoadBalanderStickinessManagerConfig.model_validate(config)

        from naylence.fame.stickiness.simple_load_balancer_stickiness_manager import (
            SimpleLoadBalancerStickinessManager,
        )

        return SimpleLoadBalancerStickinessManager(cfg)
