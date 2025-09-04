from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional, Protocol, Required, TypedDict

from naylence.fame.core import (
    DeliveryOriginType,
    FameConnector,
    FameEnvelopeHandler,
    NodeWelcomeFrame,
)
from naylence.fame.node.node_like import NodeLike


class AttachInfo(TypedDict, total=False):
    """
    Result of the attach handshake.
    """

    system_id: Required[str]
    target_system_id: Required[str]
    target_physical_path: Required[str]
    assigned_path: Required[str]
    accepted_logicals: Optional[List[str]]
    attach_expires_at: Optional[datetime]
    routing_epoch: Optional[str]
    connector: FameConnector
    parent_keys: Optional[list[dict]]


class NodeAttachClient(Protocol):
    """
    Encapsulates the NodeAttach → NodeAttachAck handshake
    over an already-started FameConnector.
    """

    async def attach(
        self,
        node: NodeLike,
        origin_type: DeliveryOriginType,
        connector: FameConnector,
        welcome_frame: NodeWelcomeFrame,
        final_handler: FameEnvelopeHandler,
        keys: Optional[list[dict]] = None,
        callback_grants: Optional[List[dict[str, Any]]] = None,
    ) -> AttachInfo:
        """
        Perform the attach handshake.

        :param connector: A started FameConnector whose handler is *not* yet final.
        :param welcome: The NodeWelcomeFrame from admission phase.
        :param final_handler: Your node's post-handshake FameHandler.
        :param keys: Optional list of keys for authentication.
        :param callback_grants: Optional list of callback grants
               for reverse connections that upstream can use to connect back.
        :returns: AttachInfo containing system_id, paths, and the connector.
        :raises: on timeout or non-success ACK
        """
        ...
