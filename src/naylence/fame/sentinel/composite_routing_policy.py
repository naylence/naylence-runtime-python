from typing import Iterable, Optional, Sequence

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.sentinel.router import Drop, RouterState, RoutingAction
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CompositeRoutingPolicy(RoutingPolicy):
    """
    Evaluates policies in order; returns the first non-Drop action.
    The final outcome is Drop() only if every policy says Drop().
    """

    def __init__(self, policies: Sequence[RoutingPolicy] | Iterable[RoutingPolicy]):
        self._policies = tuple(policies)

    async def decide(
        self,
        envelope: FameEnvelope,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> RoutingAction:
        for policy in self._policies:
            action = await policy.decide(envelope, state, context)
            if not isinstance(action, Drop):
                return action
        return Drop()  # nobody handled it
