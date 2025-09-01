"""
Authentication injection strategies for connectors.

These strategies know how to apply authentication configurations to connectors,
including setting up token providers and handling token refresh.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Optional

from naylence.fame.security.auth.auth_injection_strategy_factory import AuthInjectionStrategyConfig
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AuthInjectionStrategy(ABC):
    """
    Base class for authentication injection strategies.

    Each strategy knows how to apply a specific type of Auth
    to a connector, including initial setup and ongoing token refresh.
    """

    def __init__(self, auth_config: AuthInjectionStrategyConfig):
        self.auth_config = auth_config
        self._refresh_task: Optional[asyncio.Task] = None

    @abstractmethod
    async def apply(self, connector: Any) -> None:
        """
        Apply authentication configuration to the connector.

        This should set up initial authentication and start any
        background refresh tasks if needed.
        """
        pass

    async def cleanup(self) -> None:
        """Clean up any background tasks or resources."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
