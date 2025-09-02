from __future__ import annotations

import os
import ssl
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import Field

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.core import AuthorizationContext, FameConnector
from naylence.fame.errors.errors import FameConnectError
from naylence.fame.factory import ExpressionEvaluationPolicy
from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)
from naylence.fame.util.logging import getLogger
from naylence.fame.util.util import deserialize_model

if TYPE_CHECKING:
    from naylence.fame.grants.connection_grant import ConnectionGrant

logger = getLogger(__name__)


class WebSocketConnectorConfig(ConnectorConfig):
    """Local configuration for WebSocket connector."""

    type: str = "WebSocketConnector"
    # params: Optional[Mapping[str, Any]] = Field(default=None)
    url: Optional[str] = Field(
        default=None,
        description="WebSocket URL to connect to (required if params is not set",
    )
    auth: Optional[AuthInjectionStrategyConfig] = Field(default=None)


class WebSocketConnectorFactory(ConnectorFactory):
    """
    Builds a FameConnector from a ConnectorDirective (type='websocket').
    Handles auth token injection via:
        - subprotocol (default; browser-friendly)
        - query param
        - headers
    """

    def __init__(self, client_factory: Optional[Callable[..., Any]] = None):
        self._client_factory = client_factory or self._default_websocket_client

    @classmethod
    def supported_grant_types(cls) -> List[str]:
        """Return list of grant types this factory supports."""
        return ["WebSocketConnectionGrant", "WebSocketConnector"]

    @classmethod
    def supported_grants(cls) -> dict[str, type[ConnectionGrant]]:
        return {
            "WebSocketConnectionGrant": WebSocketConnectionGrant,
        }

    @classmethod
    def config_from_grant(
        cls,
        grant: Union[ConnectionGrant, dict[str, Any]],
        expression_evaluation_policy: Optional[
            ExpressionEvaluationPolicy
        ] = ExpressionEvaluationPolicy.ERROR,
    ) -> ConnectorConfig:
        """
        Create a WebSocketConnectorConfig from a connection grant or dictionary.

        Args:
            grant: The connection grant or dictionary to convert to a config

        Returns:
            WebSocketConnectorConfig instance

        Raises:
            ValueError: If grant type is not supported
        """
        from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant

        # Handle dictionary case - create proper grant first
        if isinstance(grant, dict):
            if grant.get("type") != "WebSocketConnectionGrant":
                raise ValueError(
                    f"WebSocketConnectorFactory only supports WebSocketConnectionGrant, got type {
                        grant.get('type')
                    }"
                )
            websocket_grant = deserialize_model(WebSocketConnectionGrant, grant)
        elif isinstance(grant, WebSocketConnectionGrant):
            websocket_grant = grant
        elif hasattr(grant, "type") and grant.type == "WebSocketConnectionGrant":
            # Convert base grant to WebSocketConnectionGrant if it has the right type
            websocket_grant = deserialize_model(
                WebSocketConnectionGrant,
                grant.model_dump(by_alias=True),
                expression_evaluation_policy=expression_evaluation_policy,
            )
        else:
            raise ValueError(
                f"WebSocketConnectorFactory only supports WebSocketConnectionGrant, got {type(grant)}"
            )

        if isinstance(websocket_grant.auth, dict):
            websocket_grant.auth = deserialize_model(
                AuthInjectionStrategyConfig,
                websocket_grant.auth,
                expression_evaluation_policy=expression_evaluation_policy,
            )

        # Convert grant to config
        return WebSocketConnectorConfig(
            type="WebSocketConnector", url=websocket_grant.url, auth=websocket_grant.auth
        )

    @classmethod
    def grant_from_config(
        cls,
        config: Union[ConnectorConfig, Dict[str, Any]],
        expression_evaluation_policy: Optional[
            ExpressionEvaluationPolicy
        ] = ExpressionEvaluationPolicy.ERROR,
    ) -> ConnectionGrant:
        """
        Create a WebSocketConnectionGrant from a connector config or dictionary.

        Args:
            config: The connector config or dictionary to convert to a grant

        Returns:
            WebSocketConnectionGrant instance

        Raises:
            ValueError: If config type is not supported
        """
        from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant

        # Handle dictionary case - create proper config first
        if isinstance(config, dict):
            if config.get("type") != "WebSocketConnector":
                raise ValueError(
                    f"WebSocketConnectorFactory only supports WebSocketConnector config, got type {
                        config.get('type')
                    }"
                )
            websocket_config = deserialize_model(
                WebSocketConnectorConfig,
                config,
                expression_evaluation_policy=expression_evaluation_policy,
            )
        elif isinstance(config, WebSocketConnectorConfig):
            websocket_config = config
        elif hasattr(config, "type") and config.type == "WebSocketConnector":
            # Convert base config to WebSocketConnectorConfig if it has the right type
            websocket_config = deserialize_model(
                WebSocketConnectorConfig,
                config.model_dump(by_alias=True),
                expression_evaluation_policy=expression_evaluation_policy,
            )
        else:
            raise ValueError(
                f"WebSocketConnectorFactory only supports WebSocketConnector config, got {type(config)}"
            )

        # Convert config to grant
        return WebSocketConnectionGrant(
            type="WebSocketConnectionGrant",
            purpose="connection",  # Default purpose for connection grants
            url=websocket_config.url,
            auth=websocket_config.auth,
        )

    async def create(
        self,
        config: Optional[WebSocketConnectorConfig | dict[str, Any]] = None,
        websocket: Optional[Any] = None,
        system_id: Optional[str] = None,
        **kwargs: Dict[str, Any],
    ) -> FameConnector:
        if not config:
            raise ValueError("Config not set")

        # Accept either real config or legacy dict for backward compatibility
        if isinstance(config, dict):
            # Convert dict to config
            config = deserialize_model(WebSocketConnectorConfig, config)

        # Create auth strategy once if needed
        auth_strategy = None
        if config.auth:
            auth_strategy = await AuthInjectionStrategyFactory.create_auth_strategy(config.auth)

        authorization_context: Optional[AuthorizationContext] = None

        if not websocket:
            url = config.url
            if not url:
                raise ValueError("WebSocket URL must be provided in config")

            subprotocols = None
            headers = None

            # Apply auth strategy to modify connection parameters if needed
            if auth_strategy:
                # Handle connection-time auth strategies
                if hasattr(auth_strategy, "get_subprotocols") and callable(
                    getattr(auth_strategy, "get_subprotocols")
                ):
                    # get_subprotocols is async for WebSocketSubprotocolStrategy
                    result = await auth_strategy.get_subprotocols()  # type: ignore
                    if isinstance(result, list):
                        subprotocols = result
                elif hasattr(auth_strategy, "modify_url"):
                    # modify_url is async for QueryParamStrategy
                    result = await auth_strategy.modify_url(url)  # type: ignore
                    if isinstance(result, str):
                        url = result

            # Construct the final URL, appending system_id if provided
            final_url = url
            if system_id:
                final_url = url + f"/{system_id}"

            websocket = await self._client_factory(final_url, subprotocols, headers)
            authorization_context = AuthorizationContext(authenticated=True, authorized=True)
        else:
            pass  # Assume websocket is already a valid WebSocket client

        # Create connector and apply post-connection auth strategy if needed
        connector = WebSocketConnector(websocket, authorization_context=authorization_context)

        if auth_strategy:
            await auth_strategy.apply(connector)

        return connector

    def _append_query_param(self, url: str, key: str, value: str) -> str:
        parts = urlparse(url)
        query = dict(parse_qsl(parts.query))
        query[key] = value
        new_query = urlencode(query)
        return urlunparse(parts._replace(query=new_query))

    def _create_ssl_context(self, url: str) -> Optional[ssl.SSLContext]:
        """
        Creates SSL context for WSS connections if SSL_CERT_FILE is set.
        Returns None for non-WSS URLs or if SSL_CERT_FILE is not set.
        """
        parsed_url = urlparse(url)
        if parsed_url.scheme != "wss":
            return None

        ssl_cert_file = os.environ.get("SSL_CERT_FILE")
        if not ssl_cert_file:
            return None

        try:
            context = ssl.create_default_context()
            context.load_verify_locations(ssl_cert_file)
            logger.debug("ssl_context_created", cert_file=ssl_cert_file, url=url)
            return context
        except Exception as e:
            logger.warning("ssl_context_creation_failed", cert_file=ssl_cert_file, error=str(e))
            return None

    async def _default_websocket_client(
        self,
        url: str,
        subprotocols: Optional[List[str]],
        headers: Optional[Dict[str, str]],
        heartbeat: int = 20,  # TODO: milliseconds?
    ):
        """
        Creates a raw WebSocket client using `websockets.connect`.
        Override this for custom WS adapters.
        Supports custom SSL CA certificates via SSL_CERT_FILE environment variable for WSS connections.
        """
        try:
            import websockets

            logger.debug("websocket_connector_connecting", url=url)

            # Create SSL context for WSS connections if SSL_CERT_FILE is set
            ssl_context = self._create_ssl_context(url)

            return await websockets.connect(
                url,
                subprotocols=subprotocols,  # type: ignore
                # extra_headers=headers,
                open_timeout=5,
                ping_interval=heartbeat,
                max_size=256 * 1024,
                ssl=ssl_context,
            )
        except OSError as ose:
            raise FameConnectError(f"cannot connect to {url}: {ose}") from ose
