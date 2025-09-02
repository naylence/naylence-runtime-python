from __future__ import annotations

from typing import Any, Optional

from naylence.fame.connector.transport_listener import TransportListener
from naylence.fame.connector.transport_listener_config import TransportListenerConfig
from naylence.fame.connector.transport_listener_factory import TransportListenerFactory


class HttpListenerConfig(TransportListenerConfig):
    """Configuration for default HTTP listener."""

    type: str = "HttpListener"


class HttpListenerFactory(TransportListenerFactory):
    """Factory for creating default HTTP listeners with lazy imports."""

    async def create(
        self,
        config: Optional[HttpListenerConfig | dict[str, Any]] = None,
        **kwargs,
    ) -> TransportListener:
        # Lazy import to avoid loading dependencies unless actually creating an instance
        from naylence.fame.connector.default_http_server import DefaultHttpServer
        from naylence.fame.connector.http_listener import HttpListener

        # Convert to our specific config type if needed
        if config and not isinstance(config, HttpListenerConfig):
            if isinstance(config, dict):
                config = HttpListenerConfig(**config)
            else:
                config = HttpListenerConfig(**config.model_dump())
        elif not config:
            config = HttpListenerConfig()

        # At this point config is definitely HttpListenerConfig
        assert isinstance(config, HttpListenerConfig)

        # Get or create the shared HTTP server for this host:port
        http_server = await DefaultHttpServer.get_or_create(host=config.host, port=config.port)

        # Extract and create authorizer if configured
        authorizer = None
        if config.authorizer:
            from naylence.fame.factory import create_resource
            from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory

            authorizer = await create_resource(AuthorizerFactory, config.authorizer)

        listener = HttpListener(
            http_server=http_server,
            authorizer=authorizer,
            **kwargs,
        )

        return listener
