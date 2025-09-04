"""Base connection grant class."""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.grants.grant import Grant

if TYPE_CHECKING:
    from naylence.fame.connector.connector_config import ConnectorConfig


class ConnectionGrant(Grant):
    """
    Base class for connection grants.

    A connection grant represents a permission to establish a connection
    with specific configuration parameters. It's returned by the NodeWelcomeFrame
    and used to create connectors for establishing connections.
    """

    type: str = Field(default="ConnectionGrant", description="Type of connection grant")

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")

    @abstractmethod
    def to_connector_config(self) -> ConnectorConfig: ...
