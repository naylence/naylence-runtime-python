"""
No authentication strategy implementation.
"""

from __future__ import annotations

from typing import Any

from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy
from naylence.fame.security.auth.no_auth_injection_strategy_factory import NoAuthInjectionStrategyConfig


class NoAuthInjectionStrategy(AuthInjectionStrategy):
    """Strategy for no authentication."""

    def __init__(self, config: NoAuthInjectionStrategyConfig):
        self.config = config

    async def apply(self, connector: Any) -> None:
        """No authentication - nothing to do."""
        pass

    async def cleanup(self) -> None:
        """Clean up any background tasks or resources."""
        pass
