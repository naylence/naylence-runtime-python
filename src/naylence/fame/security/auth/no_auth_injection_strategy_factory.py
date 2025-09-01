"""
No authentication factory module containing config and factory.
"""

from __future__ import annotations

from typing import Any

from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)


class NoAuthInjectionStrategyConfig(AuthInjectionStrategyConfig):
    """No authentication configuration."""

    type: str = "NoAuth"

    def model_dump(self, **kwargs) -> dict:
        """Override to provide backward-compatible format."""
        return {}


class NoAuthInjectionStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for NoAuthStrategy."""

    async def create(
        self, config: NoAuthInjectionStrategyConfig | dict[str, Any] | None = None, **kwargs: Any
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = NoAuthInjectionStrategyConfig(**config)

        if not config:
            config = NoAuthInjectionStrategyConfig()

        from naylence.fame.security.auth.no_auth_injection_strategy import NoAuthInjectionStrategy

        return NoAuthInjectionStrategy(config)
