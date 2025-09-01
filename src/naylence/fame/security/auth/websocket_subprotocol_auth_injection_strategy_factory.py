"""
WebSocket subprotocol authentication factory module containing config and factory.
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


class WebSocketSubprotocolAuthInjectionConfig(AuthInjectionStrategyConfig):
    """Bearer token authentication via WebSocket subprotocol."""

    type: str = "WebSocketSubprotocolAuth"
    token_provider: TokenProviderConfig = Field(description="Token provider for dynamic token acquisition")
    subprotocol_prefix: str = Field(default="bearer", description="Subprotocol prefix", alias="param")

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )


class WebSocketSubprotocolAuthInjectionStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for WebSocketSubprotocolStrategy."""

    async def create(
        self,
        config: WebSocketSubprotocolAuthInjectionConfig | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = WebSocketSubprotocolAuthInjectionConfig.model_validate(config)

        if not config:
            raise ValueError("WebSocketSubprotocolAuth config is required")

        from naylence.fame.security.auth.websocket_subprotocol_auth_injection_strategy import (
            WebSocketSubprotocolAuthInjectionStrategy,
        )

        return WebSocketSubprotocolAuthInjectionStrategy(config)
