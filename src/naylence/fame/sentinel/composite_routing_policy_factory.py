from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
    RoutingPolicyConfig,
    RoutingPolicyFactory,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CompositeRoutingPolicyConfig(RoutingPolicyConfig):
    type: str = "CompositeRoutingPolicy"
    policies: list[RoutingPolicyConfig] = Field(default_factory=list)


class CompositeRoutingPolicyFactory(RoutingPolicyFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[CompositeRoutingPolicyConfig | dict[str, Any]] = None,
        load_balancing_strategy: Optional[LoadBalancingStrategy] = None,
        **kwargs: Any,
    ) -> RoutingPolicy:
        from naylence.fame.sentinel.composite_routing_policy import (
            CompositeRoutingPolicy,
        )

        if config is None:
            config = CompositeRoutingPolicyConfig(policies=[])
        elif isinstance(config, dict):
            config = CompositeRoutingPolicyConfig(**config)

        policies = []

        for policy_config in config.policies:
            policy = await create_resource(RoutingPolicyFactory, policy_config)
            if policy:
                policies.append(policy)
            else:
                logger.warning("failed_to_create_routing_policy_from_config", config=policy_config)  # type: ignore

        if not policies:
            # Create default composite routing policy with the configured load balancing strategy
            from naylence.fame.sentinel.capability_aware_routing_policy import (
                CapabilityAwareRoutingPolicy,
            )
            from naylence.fame.sentinel.hybrid_path_routing_policy import (
                HybridPathRoutingPolicy,
            )

            policies = [
                CapabilityAwareRoutingPolicy(),
                HybridPathRoutingPolicy(load_balancing_strategy),
            ]

        return CompositeRoutingPolicy(policies)
