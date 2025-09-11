from __future__ import annotations

from typing import Optional, cast

from naylence.fame.core import (
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    NodeHeartbeatAckFrame,
    NodeHeartbeatFrame,
)
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class NodeHeartbeatFrameHandler:
    """Handler for NodeHeartbeat frames in the Sentinel."""

    def __init__(self, *, routing_node: RoutingNodeLike):
        self._routing_node_like = routing_node

    async def accept_node_heartbeat(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext],
    ):
        """Handle incoming NodeHeartbeat frames."""
        if not isinstance(envelope.frame, NodeHeartbeatFrame):
            raise ValueError(
                f"Invalid envelope frame. Expected: {NodeHeartbeatFrame}, actual: {type(envelope.frame)}"
            )

        logger.trace(
            "handling_heartbeat",
            hb_system_id=envelope.frame.system_id,
            hb_env_id=envelope.id,
            hb_corr_id=envelope.corr_id,
        )

        if context is None:
            raise RuntimeError("missing FameDeliveryContext")

        if not context.from_connector:
            raise RuntimeError("Connector in context does not match pending connector")

        # Create and send heartbeat ACK
        ack_frame = NodeHeartbeatAckFrame(
            routing_epoch=self._routing_node_like.routing_epoch, ok=True, ref_id=envelope.id
        )
        ack_env = self._routing_node_like.envelope_factory.create_envelope(
            frame=ack_frame, corr_id=envelope.corr_id
        )

        logger.debug(
            "sending_heartbeat_ack",
            hb_ack_env_id=ack_env.id,
            hb_ack_corr_id=envelope.corr_id,
        )

        # await cast(FameConnector, context.from_connector).send(ack_env)

        await self._send_and_notify(
            connector=cast(FameConnector, context.from_connector),
            envelope=ack_env,
            forward_route=envelope.frame.system_id or "unknown",
            context=context,
        )

    async def _send_and_notify(
        self,
        connector: FameConnector,
        envelope: FameEnvelope,
        forward_route: str,
        context: Optional[FameDeliveryContext] = None,
    ):
        try:
            await self._routing_node_like._dispatch_envelope_event(
                "on_forward_to_route", self._routing_node_like, forward_route, envelope, context=context
            )
            await connector.send(envelope)
        except Exception as e:
            await self._routing_node_like._dispatch_envelope_event(
                "on_forward_to_route_complete",
                self._routing_node_like,
                forward_route,
                envelope,
                error=e,
                context=context,
            )
            raise
        else:
            await self._routing_node_like._dispatch_envelope_event(
                "on_forward_to_route_complete",
                self._routing_node_like,
                forward_route,
                envelope,
                context=context,
            )
