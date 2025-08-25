from __future__ import annotations

from typing import Optional

from naylence.fame.core import (
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    KeyRequestFrame,
    parse_address,
    parse_address_components,
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
    ForwardPeer,
    ForwardUp,
    RouterState,
    RoutingAction,
)
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
)
from naylence.fame.util.logging import getLogger
from naylence.fame.util.logicals_util import is_pool_logical, matches_pool_logical
from naylence.fame.util.util import normalize_path

logger = getLogger(__name__)

_CONTROL_DROP = {"NodeHello", "NodeWelcome", "NodeReject"}
_CONTROL_UP = {"AddressBind", "AddressUnbind", "NodeHeartbeat"}

# Frames that can be routed through the normal routing pipeline
_ROUTABLE_FRAMES = {
    "Data",
    "DeliveryAck",
    "SecureOpen",
    "SecureAccept",
    "SecureClose",
    "KeyRequest",  # Allow KeyRequest to flow through routing pipeline
}


class HybridPathRoutingPolicy(RoutingPolicy):
    """
    0. Drop or bubble control frames.
    1. Deliver locally if the exact address is bound here.
    2. Forward to the exact logical child if the address is in `state.downstream`.
    3. Pool / wildcard routing via `state.pools`.
    4. Physical-prefix routing *only* when we have a non-root mount prefix.
       • exact  → DeliverLocal
       • deeper → ForwardChild(first remainder segment)
    5. Fallback: ForwardUp if we have a parent, otherwise Drop.

    Loop Prevention: Messages that originated from upstream are never forwarded
    back upstream to prevent routing loops.
    """

    def __init__(
        self,
        load_balancing_strategy: Optional[LoadBalancingStrategy] = None,
    ):
        self._lb = load_balancing_strategy or HRWLoadBalancingStrategy()

    def _origin_route_matches(self, context: Optional[FameDeliveryContext], child_segment: str) -> bool:
        """
        Check if forwarding to the given child segment would create a downstream loop.

        Returns True if the message originated from downstream and we're about to
        forward back to the same child segment it came from.
        """
        return (
            context is not None
            and context.origin_type == DeliveryOriginType.DOWNSTREAM
            and context.from_system_id == child_segment
        )

    async def decide(
        self,
        envelope: FameEnvelope,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> RoutingAction:
        frame_type = envelope.frame.type

        # ────────────────────── control frames ──────────────────────
        if frame_type in _CONTROL_DROP:
            return Drop()
        if frame_type in _CONTROL_UP:
            # Prevent looping: don't forward control frames upstream if they came from upstream
            if state.has_parent and not (context and context.origin_type == DeliveryOriginType.UPSTREAM):
                return ForwardUp()
            else:
                return Drop()

        # We route frames that are in the routable set and have a destination.
        # For KeyRequest frames, use the frame's address field instead of envelope.to
        if frame_type == "KeyRequest":
            # KeyRequest frames use the address field in the frame, not envelope.to
            if not isinstance(envelope.frame, KeyRequestFrame) or envelope.frame.address is None:
                return Drop()
            to_addr = envelope.frame.address
        else:
            # Other frames use envelope.to
            if frame_type not in _ROUTABLE_FRAMES or envelope.to is None:  # defensive
                return Drop()
            to_addr = envelope.to
        name, location = parse_address(to_addr)

        # Extract path component for routing (handle new address formats)
        _, host, path = parse_address_components(to_addr)
        if path is None:
            # Host-only format, don't do physical path routing
            path = None  # Signal that this is host-only
        elif host is not None:
            # Host+path format, use the path component
            pass
        else:
            # Traditional path-only format
            path = location

        # ───────────── 1) exact local bind  ─────────────
        if to_addr in state.local:
            return DeliverLocal(to_addr)

        # ───────────── 2) exact logical child ───────────
        seg = state.downstream_address_routes.get(to_addr)
        if seg:
            # Prevent downstream loop: if message came from downstream and we're about to
            # forward back to the same child segment, drop it
            if self._origin_route_matches(context, seg):
                return Drop()
            return ForwardChild(seg)

        seg = state.peer_address_routes.get(to_addr)
        if seg:
            return ForwardPeer(seg)

        # ───────────── 3) pool / wildcard routing ───────
        # Check for host-like pool routing first
        _, host, _ = parse_address_components(to_addr)
        if host:
            # Host-like address - check for matching pool patterns
            pool_chosen = self._find_host_pool_route(name, host, state, envelope)
            if pool_chosen:
                # Prevent downstream loop: if message came from downstream and we're about to
                # forward back to the same child segment, drop it
                if self._origin_route_matches(context, pool_chosen):
                    return Drop()
                return ForwardChild(pool_chosen)

        # Fallback: legacy path-based pool routing for backward compatibility
        if path is not None:  # Only do path-based routing if we have a path
            logical = _logical(path, state.physical_segments)
            pool = state.pools.get((name, normalize_path(logical)))
            if pool:
                chosen = self._lb.choose((name, logical), list(pool), envelope)
                if chosen:
                    # Prevent downstream loop: if message came from downstream and we're about to
                    # forward back to the same child segment, drop it
                    if self._origin_route_matches(context, chosen):
                        return Drop()
                    return ForwardChild(chosen)

        # ───────────── 4) physical-prefix routing ───────
        # Skip physical routing for host-only addresses (path is None)
        if path is not None:
            # 4) physical-prefix routing
            phys_segs = state.physical_segments
            dest_segs = [s for s in path.split("/") if s]

            if not dest_segs:
                # Empty path segments but path was not None - continue to fallback
                pass
            else:
                first = dest_segs[0]
                if first in state.peer_segments:
                    return ForwardPeer(first)

                if phys_segs and dest_segs[: len(phys_segs)] == phys_segs:
                    # (non-root mount) – existing logic…
                    remainder = dest_segs[len(phys_segs) :]
                    if not remainder:
                        return DeliverLocal(to_addr)
                    nxt = remainder[0]
                    if nxt in state.child_segments:  # guard
                        # Prevent downstream loop: if message came from downstream and we're about to
                        # forward back to the same child segment, drop it
                        if self._origin_route_matches(context, nxt):
                            return Drop()
                        return ForwardChild(nxt)

                elif not phys_segs and dest_segs:
                    # (root node) – forward to child *only if it exists*
                    if first in state.child_segments:  # NEW root rule
                        # Prevent downstream loop: if message came from downstream and we're about to
                        # forward back to the same child segment, drop it
                        if self._origin_route_matches(context, first):
                            return Drop()
                        return ForwardChild(first)

        # ───────────── 5) fallback up / drop ────────────
        # Prevent looping: don't forward upstream if the message came from upstream
        if state.has_parent and not (context and context.origin_type == DeliveryOriginType.UPSTREAM):
            return ForwardUp()
        else:
            return Drop()

    def _find_host_pool_route(
        self, name: str, host: str, state: RouterState, envelope: FameEnvelope
    ) -> Optional[str]:
        """
        Find a pool route for host-like addresses.

        Args:
            name: The participant name
            host: The host part of the address
            state: Router state containing pools
            envelope: The envelope being routed

        Returns:
            Chosen child segment or None if no pool match
        """
        # Look for pool patterns that match this host
        for (pool_name, pool_pattern), pool_members in state.pools.items():
            if pool_name != name:
                continue

            # Check if this is a host-like pool pattern
            if is_pool_logical(pool_pattern) and matches_pool_logical(host, pool_pattern):
                # Found a matching pool, choose a member
                chosen = self._lb.choose((name, pool_pattern), list(pool_members), envelope)
                if chosen:
                    return chosen

        return None


def _logical(path: str, phys: list[str]) -> str:
    """
    Remove this router's physical mount prefix from `path`.

    phys = ["R001"]
    path = "/R001/orders/*"   →  "/orders/*"
    path = "/orders/*"        →  "/orders/*"     (root node)
    """
    segs = path.lstrip("/").split("/")
    if phys and segs[: len(phys)] == phys:
        segs = segs[len(phys) :]
    return "/" + "/".join(segs) if segs else "/"
