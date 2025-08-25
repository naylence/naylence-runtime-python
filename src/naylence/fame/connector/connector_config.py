from __future__ import annotations

from naylence.fame.factory import ResourceConfig


class ConnectorConfig(ResourceConfig):
    """
    Base class for connector settings.

    • Never serialized to the wire
    • Contains runtime knobs (queue sizes, timeouts, TLS flags, etc.)
    • Used by connector factories to configure connectors in this process
    """

    type: str

    durable: bool = False
