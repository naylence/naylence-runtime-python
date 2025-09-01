from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.connector.connector_config import (
    ConnectorConfig,
)
from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.core import FameConnector
from naylence.fame.grants.connection_grant import ConnectionGrant
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)
from naylence.fame.util.util import safe_deserialize_model


class HttpStatelessConnectorConfig(ConnectorConfig):
    """Local configuration for HTTP stateless connector."""

    type: str = "HttpStatelessConnector"
    url: str
    max_queue: int = 1024
    kind: str = "http-stateless"

    # Auth fields (for backward compatibility with ConnectorDirective)
    auth: Optional[AuthInjectionStrategyConfig] = Field(default=None)
    # credentials: Optional[Mapping[str, str]] = Field(default=None)

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class HttpStatelessConnectorFactory(ConnectorFactory):
    """
    Factory for creating HTTP stateless connectors.

    Creates a connector that communicates via:
    - Outbound: HTTP POST requests to the specified outbox URL
    - Inbound: FastAPI routes that push bytes to the connector's queue
    """

    @classmethod
    def supported_grant_types(cls) -> List[str]:
        """Return list of connection grant types that this factory can handle."""
        return [
            "HttpConnectionGrant",
            "HttpStatelessConnector",  # Legacy support
        ]

    @classmethod
    def config_from_grant(cls, grant: Union[ConnectionGrant, Dict[str, Any]]) -> ConnectorConfig:
        """
        Create an HttpStatelessConnectorConfig from a connection grant or dictionary.

        Args:
            grant: The connection grant or dictionary to convert to a config

        Returns:
            HttpStatelessConnectorConfig instance

        Raises:
            ValueError: If grant type is not supported
        """
        # Handle dictionary case - create proper grant first
        if isinstance(grant, dict):
            if grant.get("type") != "HttpConnectionGrant":
                raise ValueError(
                    f"HttpStatelessConnectorFactory only supports HttpConnectionGrant, got type {
                        grant.get('type')
                    }"
                )
            http_grant = safe_deserialize_model(HttpConnectionGrant, grant)
        elif isinstance(grant, HttpConnectionGrant):
            http_grant = grant
        elif hasattr(grant, "type") and grant.type == "HttpConnectionGrant":
            # Convert base grant to HttpConnectionGrant if it has the right type
            http_grant = safe_deserialize_model(HttpConnectionGrant, grant.model_dump())
        else:
            raise ValueError(
                f"HttpStatelessConnectorFactory only supports HttpConnectionGrant, got {type(grant)}"
            )

        if isinstance(http_grant.auth, dict):
            http_grant.auth = safe_deserialize_model(AuthInjectionStrategyConfig, http_grant.auth)

        # Convert grant to config
        return HttpStatelessConnectorConfig(
            type="HttpStatelessConnector",
            url=http_grant.url,
            max_queue=1024,  # TODO: remove hardcoded
            kind="http-stateless",
            auth=http_grant.auth,
        )

    async def create(
        self,
        config: Optional[HttpStatelessConnectorConfig | dict[str, Any]] = None,
        **kwargs: Dict[str, Any],
    ) -> FameConnector:
        # Check if we're being passed an existing connector (transport primitive pattern)
        websocket = kwargs.get("websocket")
        if websocket and isinstance(websocket, HttpStatelessConnector):
            # Return existing connector directly
            return websocket

        if not config:
            raise ValueError("Config not set")

        # Accept either real config or legacy dict for backward compatibility
        if isinstance(config, dict):
            # Convert dict to config
            config = HttpStatelessConnectorConfig.model_validate(config)

        if not isinstance(config, HttpStatelessConnectorConfig):
            raise ValueError("HttpStatelessConnectorConfig required")

        # if not config.params:
        #     raise ValueError("Invalid configuration: params not set")

        url = config.url
        if not url:
            raise ValueError("url is required in config params")

        max_queue = config.max_queue or 1024

        # Create connector first
        connector = HttpStatelessConnector(
            url=url,
            max_queue=max_queue,
        )

        # Apply authentication strategy if configured
        if config.auth:
            strategy = await AuthInjectionStrategyFactory.create_auth_strategy(config.auth)
            await strategy.apply(connector)

        return connector
