from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

from naylence.fame.connector.http_server_config import HttpServerConfig
from naylence.fame.connector.http_server_factory import HttpServerFactory

if TYPE_CHECKING:
    from naylence.fame.connector.http_server import HttpServer


class DefaultHttpServerConfig(HttpServerConfig):
    """Configuration for the default FastAPI/Uvicorn HTTP server."""

    type: str = "DefaultHttpServer"


class DefaultHttpServerFactory(HttpServerFactory):
    """Factory for creating default HTTP servers with lazy imports."""

    async def create(
        self,
        config: Optional[DefaultHttpServerConfig | dict[str, Any]] = None,
        **kwargs: Dict[str, Any],
    ) -> HttpServer:
        # Lazy import to avoid circular dependencies
        from naylence.fame.connector.default_http_server import DefaultHttpServer

        # Convert to our specific config type if needed
        if config is None:
            config_obj = DefaultHttpServerConfig()
        elif isinstance(config, DefaultHttpServerConfig):
            config_obj = config
        elif isinstance(config, dict):
            config_obj = DefaultHttpServerConfig(**config)
        else:
            raise TypeError("config must be None, a dict, or a DefaultHttpServerConfig instance")

        # Use the registry to get or create a shared server
        return await DefaultHttpServer.get_or_create(host=config_obj.host, port=config_obj.port)
