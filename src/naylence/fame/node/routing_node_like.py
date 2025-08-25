from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

from naylence.fame.core import (
    AuthorizationContext,
    DeliveryOriginType,
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.node.node_like import NodeLike

if TYPE_CHECKING:
    from naylence.fame.connector.connector_config import ConnectorConfig


@runtime_checkable
class RoutingNodeLike(NodeLike, Protocol):
    """Protocol for nodes that can route frames to downstream connectors."""

    @property
    def routing_epoch(self) -> str:
        """Get the current routing epoch for this routing node."""
        ...

    async def deliver_local(
        self,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        """Deliver envelope to a local address."""
        ...

    async def forward_to_route(
        self,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        """Forward envelope to a downstream route."""
        ...

    async def forward_to_peer(
        self,
        peer_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        """Forward envelope to a peer."""
        ...

    async def forward_to_peers(
        self,
        envelope: FameEnvelope,
        peers: Optional[list[str]] = None,
        exclude_peers: Optional[list[str]] = None,
        context: Optional[FameDeliveryContext] = None,
    ):
        """Forward envelope to multiple peers."""
        ...

    async def forward_upstream(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None):
        """Forward envelope upstream."""
        ...

    async def remove_downstream_route(self, segment: str, *, stop: bool = True):
        """Remove a downstream route."""
        ...

    async def remove_peer_route(self, segment: str, *, stop: bool = True):
        """Remove a peer route."""
        ...

    def _downstream_connector(self, system_id: str) -> Optional[FameConnector]:
        """Get downstream connector for a system_id/route."""
        ...

    async def create_origin_connector(
        self,
        *,
        origin_type: DeliveryOriginType,
        system_id: str,
        connector_config: ConnectorConfig,
        authorization: Optional[AuthorizationContext] = None,
        **kwargs: Any,
    ) -> FameConnector: ...
