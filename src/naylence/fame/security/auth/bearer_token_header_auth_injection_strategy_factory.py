"""
Bearer token header authentication factory module containing config and factory.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)
from naylence.fame.security.auth.token_provider_factory import TokenProviderConfig


class BearerTokenHeaderAuthInjectionStrategyConfig(AuthInjectionStrategyConfig):
    """Bearer token authentication via HTTP Authorization header."""

    type: str = "BearerTokenHeaderAuth"
    token_provider: TokenProviderConfig = Field(description="Token provider for dynamic token acquisition")
    header_name: str = Field(default="Authorization", description="HTTP header name", alias="param")

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )

    def model_dump(self, **kwargs) -> dict:
        """Override to provide backward-compatible format."""
        super().model_dump(**kwargs)
        return {
            "scheme": "bearer",
            "token": "[DYNAMIC]",
            "style": "header",
            "param": self.header_name,
        }


class BearerTokenHeaderAuthInjectionStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for BearerTokenHeaderStrategy."""

    async def create(
        self,
        config: BearerTokenHeaderAuthInjectionStrategyConfig | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = BearerTokenHeaderAuthInjectionStrategyConfig.model_validate(config)

        if not config:
            raise ValueError("BearerTokenHeaderAuth config is required")

        from naylence.fame.security.auth.bearer_token_header_auth_injection_strategy import (
            BearerTokenHeaderAuthInjectionStrategy,
        )

        return BearerTokenHeaderAuthInjectionStrategy(config)
