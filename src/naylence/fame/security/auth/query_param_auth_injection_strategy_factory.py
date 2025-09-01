"""
Query parameter authentication factory module containing config and factory.
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


class QueryParamAuthInjectionStrategyConfig(AuthInjectionStrategyConfig):
    """Authentication via URL query parameter."""

    type: str = "QueryParamAuth"
    token_provider: TokenProviderConfig = Field(description="Token provider for dynamic token acquisition")
    param_name: str = Field(default="token", description="Query parameter name", alias="param")

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
            "style": "query",
            "param": self.param_name,
        }


class QueryParamAuthInjectionStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for QueryParamStrategy."""

    async def create(
        self, config: QueryParamAuthInjectionStrategyConfig | dict[str, Any] | None = None, **kwargs: Any
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = QueryParamAuthInjectionStrategyConfig.model_validate(config)

        if not config:
            raise ValueError("QueryParamAuth config is required")

        from naylence.fame.security.auth.query_param_auth_injection_strategy import (
            QueryParamAuthInjectionStrategy,
        )

        return QueryParamAuthInjectionStrategy(config)
