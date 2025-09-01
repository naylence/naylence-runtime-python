"""HTTP connection grant implementation."""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from naylence.fame.grants.connection_grant import ConnectionGrant
from naylence.fame.security.auth.auth_config import Auth


class HttpConnectionGrant(ConnectionGrant):
    """
    Connection grant for HTTP stateless connections.

    Contains configuration parameters needed to establish an HTTP stateless connection,
    based on the structure of HttpStatelessConnectorConfig.
    """

    type: str = Field(default="HttpConnectionGrant", description="Type of connection grant")
    url: str = Field(description="HTTP URL for the connection")
    max_queue: int = Field(default=1024, description="Maximum queue size")
    kind: str = Field(default="http-stateless", description="Kind of HTTP connection")
    auth: Optional[Auth] = Field(default=None, description="Authentication configuration")
