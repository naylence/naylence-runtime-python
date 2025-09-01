from __future__ import annotations

from abc import ABC, abstractmethod


class SessionManager(ABC):
    """
    Abstract base class for session managers that handle node lifecycle operations.

    Session managers are responsible for managing the lifecycle of node connections,
    whether to upstream parents (UpstreamSessionManager) or for root sentinels
    (RootSessionManager).
    """

    @abstractmethod
    async def start(self, *, wait_until_ready: bool = True) -> None:
        """
        Start the session manager and begin managing the session lifecycle.

        Args:
            wait_until_ready: Whether to wait until the session is fully established
                            before returning. If True, this method will block until
                            the session is ready for use.
        """
        pass

    @abstractmethod
    async def stop(self) -> None:
        """
        Stop the session manager and clean up all resources.

        This should gracefully shut down any active connections, cancel background
        tasks, and release all resources.
        """
        pass
