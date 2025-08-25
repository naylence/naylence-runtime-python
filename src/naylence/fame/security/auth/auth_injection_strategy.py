"""
Authentication injection strategies for connectors.

These strategies know how to apply authentication configurations to connectors,
including setting up token providers and handling token refresh.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import List, Optional

from naylence.fame.core import FameConnector, create_resource
from naylence.fame.security.auth.auth_config import (
    BearerTokenHeaderAuth,
    ConnectorAuth,
    QueryParamAuth,
    WebSocketSubprotocolAuth,
)
from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import TokenProviderFactory
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AuthInjectionStrategy(ABC):
    """
    Base class for authentication injection strategies.

    Each strategy knows how to apply a specific type of ConnectorAuth
    to a connector, including initial setup and ongoing token refresh.
    """

    def __init__(self, auth_config: ConnectorAuth):
        self.auth_config = auth_config
        self._refresh_task: Optional[asyncio.Task] = None

    @abstractmethod
    async def apply(self, connector: FameConnector) -> None:
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


class NoAuthStrategy(AuthInjectionStrategy):
    """Strategy for no authentication."""

    async def apply(self, connector: FameConnector) -> None:
        # Nothing to do for no auth
        pass


class BearerTokenHeaderStrategy(AuthInjectionStrategy):
    """Strategy for Bearer token in Authorization header."""

    async def apply(self, connector: FameConnector) -> None:
        if not isinstance(self.auth_config, BearerTokenHeaderAuth):
            raise ValueError(f"Expected BearerTokenHeaderAuth, got {type(self.auth_config)}")

        # Create token provider
        token_provider = await create_resource(TokenProviderFactory, self.auth_config.token_provider)

        # Set initial token
        await self._update_auth_header(connector, token_provider)

        # Start background refresh if needed
        self._start_refresh_task(connector, token_provider)

    async def _update_auth_header(self, connector: FameConnector, token_provider: TokenProvider) -> None:
        """Update the connector's auth header with current token."""
        token = await token_provider.get_token()
        auth_header = f"Bearer {token.value}"

        # Use the connector's set_auth_header method if available
        if hasattr(connector, "set_auth_header"):
            getattr(connector, "set_auth_header")(auth_header)
        else:
            logger.warning(f"Connector {type(connector)} doesn't support set_auth_header")

    def _start_refresh_task(self, connector: FameConnector, token_provider: TokenProvider) -> None:
        """Start background task to refresh token when needed."""

        async def refresh_loop():
            while True:
                try:
                    token = await token_provider.get_token()

                    # Calculate sleep time (refresh 30 seconds before expiry)
                    if token.expires_at:
                        import datetime

                        now = datetime.datetime.now(datetime.timezone.utc)
                        time_until_expiry = (token.expires_at - now).total_seconds()
                        sleep_time = max(time_until_expiry - 30, 60)  # At least 60 seconds
                    else:
                        sleep_time = 3600  # 1 hour default for tokens without expiry

                    await asyncio.sleep(sleep_time)

                    # Refresh the token
                    await self._update_auth_header(connector, token_provider)
                    logger.debug("auth_token_refreshed", connector_type=type(connector).__name__)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("auth_token_refresh_failed", error=str(e), exc_info=True)
                    # Wait a bit before retrying
                    await asyncio.sleep(60)

        self._refresh_task = asyncio.create_task(refresh_loop())


class WebSocketSubprotocolStrategy(AuthInjectionStrategy):
    """Strategy for WebSocket subprotocol authentication."""

    async def apply(self, connector: FameConnector) -> None:
        # For WebSocket subprotocol auth, the authentication is set during connection
        # establishment, not after the connector is created. This is handled in the factory.
        pass

    async def get_subprotocols(self) -> List[str]:
        """Get subprotocols for WebSocket connection."""
        if not isinstance(self.auth_config, WebSocketSubprotocolAuth):
            return []

        # Create token provider from config
        token_provider: TokenProvider = await create_resource(
            TokenProviderFactory, self.auth_config.token_provider
        )

        # Get current token and create subprotocol list
        token = await token_provider.get_token()
        if token is None or not token.value:
            return []
        return [self.auth_config.subprotocol_prefix, token.value]


class QueryParamStrategy(AuthInjectionStrategy):
    """Strategy for query parameter authentication."""

    async def apply(self, connector: FameConnector) -> None:
        # For query param auth, the token is added to the URL during
        # connection establishment, not after the connector is created.
        # This is handled in the factory.
        pass

    async def modify_url(self, url: str) -> str:
        """Modify URL to include auth query parameters."""
        if not isinstance(self.auth_config, QueryParamAuth):
            return url

        # Create token provider from config
        token_provider = await create_resource(TokenProviderFactory, self.auth_config.token_provider)

        # Get current token and modify URL
        token = await token_provider.get_token()

        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        parts = urlparse(url)
        query = dict(parse_qsl(parts.query))
        query[self.auth_config.param_name] = token.value
        new_query = urlencode(query)
        return urlunparse(parts._replace(query=new_query))
