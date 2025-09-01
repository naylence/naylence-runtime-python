"""Base connection grant class."""

from __future__ import annotations

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.grants.grant import Grant


class ConnectionGrant(Grant):
    """
    Base class for connection grants.

    A connection grant represents a permission to establish a connection
    with specific configuration parameters. It's returned by the NodeWelcomeFrame
    and used to create connectors for establishing connections.
    """

    type: str = Field(default="ConnectionGrant", description="Type of connection grant")

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")
