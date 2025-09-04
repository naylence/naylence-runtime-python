"""HTTP connection grant implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from pydantic import Field

from naylence.fame.grants.connection_grant import ConnectionGrant

if TYPE_CHECKING:
    from naylence.fame.connector.connector_config import ConnectorConfig


class HttpConnectionGrant(ConnectionGrant):
    """
    Connection grant for HTTP stateless connections.

    Contains configuration parameters needed to establish an HTTP stateless connection,
    based on the structure of HttpStatelessConnectorConfig.
    """

    type: str = Field(default="HttpConnectionGrant", description="Type of connection grant")
    url: str = Field(description="HTTP URL for the connection")
    auth: Optional[Any] = Field(default=None, description="Authentication configuration")

    def to_connector_config(self) -> ConnectorConfig:
        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        return HttpStatelessConnectorConfig(url=self.url, auth=self.auth)
