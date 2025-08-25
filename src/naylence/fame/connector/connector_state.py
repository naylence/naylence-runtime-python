"""
Connector state management for Fame connectors.

This module defines the states that connectors can be in throughout their lifecycle.
"""

from enum import Enum


class ConnectorState(Enum):
    """
    Enumeration of possible connector states.

    Represents the lifecycle states that a Fame connector can be in:
    - UNKNOWN: Initial or indeterminate state
    - INITIALIZED: Connector has been created and configured
    - STARTED: Connector is actively running and processing messages
    - STOPPED: Connector has been stopped but may be restartable
    - CLOSED: Connector has been permanently closed and cannot be restarted
    """

    UNKNOWN = "unknown"
    INITIALIZED = "initialized"
    STARTED = "started"
    STOPPED = "stopped"
    CLOSED = "closed"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"ConnectorState.{self.name}"

    @property
    def is_active(self) -> bool:
        """Return True if the connector is in an active state."""
        return self in (ConnectorState.STARTED,)

    @property
    def is_inactive(self) -> bool:
        """Return True if the connector is in an inactive state."""
        return self in (ConnectorState.STOPPED, ConnectorState.CLOSED)

    @property
    def can_start(self) -> bool:
        """Return True if the connector can be started from this state."""
        return self in (ConnectorState.INITIALIZED, ConnectorState.STOPPED)

    @property
    def can_stop(self) -> bool:
        """Return True if the connector can be stopped from this state."""
        return self in (ConnectorState.STARTED,)

    @property
    def can_close(self) -> bool:
        """Return True if the connector can be closed from this state."""
        return self in (
            ConnectorState.INITIALIZED,
            ConnectorState.STARTED,
            ConnectorState.STOPPED,
        )
