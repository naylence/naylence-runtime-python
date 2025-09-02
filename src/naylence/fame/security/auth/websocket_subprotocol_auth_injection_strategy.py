"""
WebSocket subprotocol authentication strategy implementation.
"""

from __future__ import annotations

from typing import Any, List

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy
from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import TokenProviderFactory
from naylence.fame.security.auth.websocket_subprotocol_auth_injection_strategy_factory import (
    WebSocketSubprotocolAuthInjectionConfig,
)


class WebSocketSubprotocolAuthInjectionStrategy(AuthInjectionStrategy):
    """Strategy for WebSocket subprotocol authentication."""

    def __init__(self, config: WebSocketSubprotocolAuthInjectionConfig):
        self.config = config

    async def apply(self, connector: Any) -> None:
        """For WebSocket subprotocol auth, the authentication is set during connection establishment."""
        pass

    async def get_subprotocols(self) -> List[str]:
        """Get subprotocols for WebSocket connection."""
        # Create token provider from config
        token_provider: TokenProvider = await create_resource(
            TokenProviderFactory, self.config.token_provider
        )

        # Get current token and create subprotocol list
        token = await token_provider.get_token()
        if token is None or not token.value:
            return []
        return [self.config.subprotocol_prefix, token.value]

    async def cleanup(self) -> None:
        """Clean up any background tasks or resources."""
        pass
