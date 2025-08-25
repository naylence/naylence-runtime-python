from __future__ import annotations

from typing import List, Optional, Set

from naylence.fame.core import (
    DataFrame,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.sentinel.load_balancing.hrw_load_balancing_strategy import (
    HRWLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Drop,
    ForwardChild,
    ForwardUp,
    RouterState,
    RoutingAction,
)
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
)
from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class CapabilityAwareRoutingPolicy(RoutingPolicy):
    """
    AND-semantics:
      • Every capability in `envelope.capabilities`
        must be satisfied by the chosen route.
    """

    def __init__(
        self,
        load_balancing_strategy: Optional[LoadBalancingStrategy] = None,
    ):
        self._lb = load_balancing_strategy or HRWLoadBalancingStrategy()

    # ---------------------------------------------------------------- decide

    async def decide(
        self,
        envelope: FameEnvelope,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> RoutingAction:
        from naylence.fame.node.node import get_node

        resolve_address_by_capability = (
            state.resolve_address_by_capability or get_node()._service_manager.resolve_address_by_capability
        )
        # 0) If caller already gave an explicit address → defer to normal path-policy
        if envelope.to:
            return Drop()

        # 1) We only route capability lists for data payloads
        if not isinstance(envelope.frame, DataFrame):
            return Drop()

        caps: Optional[List[str]] = envelope.capabilities
        if not caps:
            return Drop()

        # --------------------------------------------------------------------
        # 2) Can *this* node satisfy ALL caps locally?
        #    (ServiceManager only knows local services.)
        try:
            local_addr = await resolve_address_by_capability(caps)
        except Exception:
            local_addr = None

        if local_addr and local_addr in state.local:
            return DeliverLocal(local_addr)

        # --------------------------------------------------------------------
        # 3) Otherwise pick a child segment that advertises *all* caps.
        #
        #    state.capabilities: {cap -> {addr -> segment}}
        #
        provider_segs: Optional[Set[str]] = None

        for cap in caps:
            routes = state.capabilities.get(cap)
            if not routes:  # no child provides this cap
                provider_segs = set()  # cuts search early
                break

            segs_for_cap = set(routes.values())
            provider_segs = (
                segs_for_cap if provider_segs is None else provider_segs & segs_for_cap  # intersection
            )
            if not provider_segs:
                break  # early exit – impossible match

        if provider_segs:
            # simple deterministic pick – could plug HRW / RR here
            # chosen_seg = next(iter(provider_segs))
            chosen_seg = self._lb.choose(tuple(caps), list(provider_segs), envelope)
            assert chosen_seg, "No segment chosen for capability-aware routing"
            return ForwardChild(chosen_seg)

        # --------------------------------------------------------------------
        # 4) No match locally or in children → forward upstream if we have one.
        if state.has_parent:
            return ForwardUp()

        return Drop()
