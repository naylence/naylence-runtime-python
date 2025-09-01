"""WebSocket connection grant implementation."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.grants.connection_grant import ConnectionGrant


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
