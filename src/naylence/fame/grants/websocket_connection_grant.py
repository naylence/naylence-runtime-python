"""WebSocket connection grant implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from pydantic import Field

from naylence.fame.grants.connection_grant import ConnectionGrant

if TYPE_CHECKING:
    from naylence.fame.connector.connector_config import ConnectorConfig


class WebSocketConnectionGrant(ConnectionGrant):
    """
    Connection grant for WebSocket connections.

    Contains configuration parameters needed to establish a WebSocket connection,
    based on the structure of WebSocketConnectorConfig.
    """

    type: str = Field(default="WebSocketConnectionGrant", description="Type of connection grant")
    url: Optional[str] = Field(
        default=None, description="WebSocket URL to connect to (required if params is not set)"
    )
    auth: Optional[Any] = Field(default=None, description="Authentication configuration")

    def to_connector_config(self) -> ConnectorConfig:
        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        return WebSocketConnectorConfig(url=self.url, auth=self.auth)
