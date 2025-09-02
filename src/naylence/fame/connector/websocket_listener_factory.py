from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Optional, cast

from naylence.fame.connector.transport_listener import TransportListener
from naylence.fame.connector.transport_listener_config import TransportListenerConfig
from naylence.fame.connector.transport_listener_factory import TransportListenerFactory

if TYPE_CHECKING:
    from naylence.fame.security.auth.token_verifier import TokenVerifier


VAR_WEBSOCKET_LISTENER_PORT = "FAME_WEBSOCKET_LISTENER_PORT"


class WebSocketListenerConfig(TransportListenerConfig):
    """Configuration for WebSocket listener."""

    type: str = "WebSocketListener"


class WebSocketListenerFactory(TransportListenerFactory):
    """Factory for creating WebSocket listeners with lazy imports."""

    is_default: bool = True

    async def create(
        self,
        config: Optional[WebSocketListenerConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> TransportListener:
        # Lazy import to avoid loading dependencies unless actually creating an instance
        from naylence.fame.connector.default_http_server import DefaultHttpServer
        from naylence.fame.connector.websocket_listener import WebSocketListener

        # Convert to our specific config type if needed
        if isinstance(config, dict):
            config = WebSocketListenerConfig.model_validate(config)
        else:
            assert isinstance(config, WebSocketListenerConfig)

        # At this point config is definitely WebSocketListenerConfig
        assert isinstance(config, WebSocketListenerConfig)

        websocket_port = config.port or int(os.getenv(VAR_WEBSOCKET_LISTENER_PORT) or 0)

        # Get or create the shared HTTP server for this host:port
        # WebSocket listener reuses the HTTP server just like HTTP listener
        http_server = await DefaultHttpServer.get_or_create(host=config.host, port=websocket_port)

        # Extract token verifier from kwargs if provided - validate it's the correct type
        token_verifier_arg = kwargs.pop("token_verifier", None)
        token_verifier: Optional[TokenVerifier] = None

        if token_verifier_arg and hasattr(token_verifier_arg, "verify"):
            token_verifier = cast("TokenVerifier", token_verifier_arg)

        # Extract and create authorizer if configured
        authorizer = None
        if config.authorizer:
            from naylence.fame.factory import create_resource
            from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory

            authorizer = await create_resource(AuthorizerFactory, config.authorizer)

        listener = WebSocketListener(
            http_server=http_server,
            token_verifier=token_verifier,
            authorizer=authorizer,
            **kwargs,
        )

        return listener
