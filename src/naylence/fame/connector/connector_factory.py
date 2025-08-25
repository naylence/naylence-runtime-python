from __future__ import annotations

from typing import TypeVar

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import FameConnector, ResourceFactory

C = TypeVar("C", bound=ConnectorConfig)


class ConnectorFactory(ResourceFactory[FameConnector, C]): ...
