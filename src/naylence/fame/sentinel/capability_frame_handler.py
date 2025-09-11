from __future__ import annotations

from collections import defaultdict
from typing import Optional

from naylence.fame.core import (
    CapabilityAdvertiseAckFrame,
    CapabilityAdvertiseFrame,
    CapabilityWithdrawAckFrame,
    CapabilityWithdrawFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.sentinel.route_manager import RouteManager
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CapabilityFrameHandler:
    """Handler for CapabilityAdvertise and CapabilityWithdraw frames in the Sentinel."""

    def __init__(
        self,
        *,
        routing_node: RoutingNodeLike,
        route_manager: RouteManager,
        upstream_connector,
    ):
        self._routing_node_like = routing_node
        self._route_manager = route_manager
        self._cap_routes: dict[str, dict[FameAddress, str]] = defaultdict(dict)
        self._upstream_connector = upstream_connector

    @property
    def cap_routes(self) -> dict[str, dict[FameAddress, str]]:
        """Access to capability routes for external components like RouterState."""
        return self._cap_routes

    async def accept_capability_advertise(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ):
        """Handle incoming CapabilityAdvertise frames."""
        frame = envelope.frame
        if not isinstance(frame, CapabilityAdvertiseFrame):
            raise ValueError("Expected CapabilityAdvertiseFrame")

        seg = self._get_source_system_id(context)
        if not seg or seg not in self._route_manager.downstream_routes:
            return  # unknown child

        first_global = False
        for cap in frame.capabilities:
            # self._service_manager._capability_map[cap] = frame.address
            routes = self._cap_routes[cap]
            if not routes:  # capability not visible yet
                first_global = True
            routes[frame.address] = seg  # address -> segment

        # ACK down
        ack = CapabilityAdvertiseAckFrame(
            address=frame.address, capabilities=frame.capabilities, ok=True, ref_id=envelope.id
        )

        ack_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            security=context.security if context else None,
            stickiness_required=context.stickiness_required if context else None,
            sticky_sid=context.sticky_sid if context else None,
        )

        await self._routing_node_like.forward_to_route(
            seg,
            self._routing_node_like.envelope_factory.create_envelope(frame=ack, corr_id=envelope.corr_id),
            ack_context,
        )

        # propagate only when capability appears globally
        if first_global and self._upstream_connector():
            await self._routing_node_like.forward_upstream(envelope, ack_context)

    async def accept_capability_withdraw(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ):
        """Handle incoming CapabilityWithdraw frames."""
        frame = envelope.frame
        if not isinstance(frame, CapabilityWithdrawFrame):
            raise ValueError("Expected CapabilityWithdrawFrame")

        seg = self._get_source_system_id(context)
        if not seg:
            return

        vanished_global = False
        for cap in frame.capabilities:
            routes = self._cap_routes.get(cap)
            if not routes:
                continue
            # Only remove if the address matches & belonged to this segment
            if routes.get(frame.address) == seg:
                del routes[frame.address]
                if not routes:  # last address gone
                    del self._cap_routes[cap]
                    vanished_global = True

        # ACK
        ack = CapabilityWithdrawAckFrame(
            address=frame.address, capabilities=frame.capabilities, ok=True, ref_id=envelope.id
        )

        ack_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            security=context.security if context else None,
            stickiness_required=context.stickiness_required if context else None,
            sticky_sid=context.sticky_sid if context else None,
        )

        await self._routing_node_like.forward_to_route(
            seg,
            self._routing_node_like.envelope_factory.create_envelope(
                frame=ack,
                corr_id=envelope.corr_id,
            ),
            ack_context,
        )

        # propagate only when capability vanished everywhere
        if vanished_global and self._upstream_connector():
            await self._routing_node_like.forward_upstream(envelope, ack_context)

    def _get_source_system_id(self, context: Optional[FameDeliveryContext]):
        source_system_id = None
        if context and context.from_system_id:
            source_system_id = context.from_system_id
        return source_system_id
