from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Optional, TypeVar

from naylence.fame.connector.transport_listener_config import TransportListenerConfig
from naylence.fame.core.util.resource_factory_registry import ResourceFactory

if TYPE_CHECKING:
    from naylence.fame.connector.transport_listener import TransportListener

T = TypeVar("T", bound=TransportListenerConfig)


class TransportListenerFactory(ResourceFactory["TransportListener", T]):
    """
    Abstract factory for creating transport listeners.

    Transport listeners manage the network server lifecycle tied to node lifecycle.
    They start when a node is initialized and stop when a node stops.
    """

    @abstractmethod
    async def create(
        self,
        config: Optional[T | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> TransportListener:
        """
        Create a transport listener instance.

        Args:
            config: Transport listener configuration
            **kwargs: Additional creation parameters

        Returns:
            Transport listener instance
        """
        pass
