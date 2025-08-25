from __future__ import annotations

from typing import Optional

from naylence.fame.core import (
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.sentinel.route_manager import RouteManager
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CreditUpdateFrameHandler:
    """Handler for CreditUpdate frames in the Sentinel."""

    def __init__(
        self,
        *,
        routing_node: RoutingNodeLike,
        route_manager: RouteManager,
    ):
        self._routing_node_like = routing_node
        self._route_manager = route_manager

    async def accept_credit_update(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming CreditUpdate frames."""
        if not envelope.flow_id:
            logger.warning("No peer for flow %s - dropping credit update", envelope.flow_id)
            return

        peer = self._route_manager._flow_routes.get(envelope.flow_id)
        if not peer:
            logger.warning("No peer for flow %s - dropping credit update", envelope.flow_id)
            return
        if context and peer is context.from_connector:  # already at the peer
            return

        await peer.send(envelope)
