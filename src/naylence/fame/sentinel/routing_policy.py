from abc import ABC, abstractmethod
from typing import Optional, TypeVar

from pydantic import ConfigDict

from naylence.fame.core import (
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)
from naylence.fame.sentinel.router import RouterState, RoutingAction


class RoutingPolicy(ABC):
    @abstractmethod
    async def decide(
        self,
        envelope: FameEnvelope,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> RoutingAction:
        pass


class RoutingPolicyConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "RoutingPolicy"


C = TypeVar("C", bound=RoutingPolicyConfig)


class RoutingPolicyFactory(ResourceFactory[RoutingPolicy, C]):
    @staticmethod
    async def create_routing_policy(
        load_balancing_strategy: LoadBalancingStrategy,
    ) -> RoutingPolicy:
        routing_policy = await create_default_resource(
            RoutingPolicyFactory, load_balancing_strategy=load_balancing_strategy
        )

        assert routing_policy, "Failed to create default routing policy"

        return routing_policy
