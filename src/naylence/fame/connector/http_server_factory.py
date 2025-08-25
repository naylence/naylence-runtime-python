from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional, TypeVar

from naylence.fame.connector.http_server_config import HttpServerConfig
from naylence.fame.factory import ResourceFactory

if TYPE_CHECKING:
    from naylence.fame.connector.http_server import HttpServer

T = TypeVar("T", bound=HttpServerConfig)


class HttpServerFactory(ResourceFactory["HttpServer", T]):
    """
    Abstract factory for creating HTTP servers.

    HTTP servers manage the HTTP server lifecycle and can be shared
    across multiple listeners that need the same host/port combination.
    """

    @abstractmethod
    async def create(
        self,
        config: Optional[T | dict[str, Any]] = None,
        **kwargs: Dict[str, Any],
    ) -> HttpServer:
        """
        Create an HTTP server instance.

        Args:
            config: HTTP server configuration
            **kwargs: Additional creation parameters

        Returns:
            HTTP server instance
        """
        pass
