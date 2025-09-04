from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike


class TransportListener(ABC):
    """
    Abstract base class for transport listeners.

    Transport listeners handle network-level ingress connections (HTTP, WebSocket, etc.)
    and manage the server lifecycle tied to node lifecycle.
    """

    @abstractmethod
    async def on_node_started(self, node: NodeLike) -> None:
        """Called when the node has started."""
        pass

    @abstractmethod
    async def on_node_stopped(self, node: NodeLike) -> None:
        """Called when the node is stopping."""
        pass

    def get_callback_grant(self) -> Optional[dict[str, Any]]:
        """
        Return a descriptor that can be used to create callback grants
        for this listener. This will be used to automatically derive
        callback_grants in NodeAttachFrame for reverse admission.

        Returns:
            Dictionary containing connector type and configuration
        """
        return None

    def as_callback_grant(self) -> Optional[dict[str, Any]]:
        """
        Return a connector configuration that can be used by parents to connect
        to this listener for reverse connections.

        Returns:
            Dictionary with connector configuration or None if not supported
        """
        return self.get_callback_grant()
