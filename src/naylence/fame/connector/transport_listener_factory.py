from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Optional, TypeVar

from naylence.fame.connector.transport_listener_config import TransportListenerConfig
from naylence.fame.factory import ResourceFactory, create_default_resource, create_resource

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

    async def create_transport_listener(
        self,
        config: Optional[T | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> Optional[TransportListener]:
        """
        Create a transport listener instance.

        Args:
            config: Transport listener configuration
            **kwargs: Additional creation parameters

        Returns:
            Transport listener instance
        """
        if config:
            return await create_resource(TransportListenerFactory, config=config, **kwargs)

        return await create_default_resource(TransportListenerFactory, **kwargs)
