"""
Bearer token header authentication strategy implementation.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from naylence.fame.core import FameConnector
from naylence.fame.factory import create_resource
from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy
from naylence.fame.security.auth.bearer_token_header_auth_injection_strategy_factory import (
    BearerTokenHeaderAuthInjectionStrategyConfig,
)
from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import TokenProviderFactory
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class BearerTokenHeaderAuthInjectionStrategy(AuthInjectionStrategy):
    """Strategy for Bearer token in Authorization header."""

    def __init__(self, config: BearerTokenHeaderAuthInjectionStrategyConfig):
        self.config = config
        self._refresh_task: Optional[asyncio.Task] = None

    async def apply(self, connector: Any) -> None:
        """Apply authentication configuration to the connector."""
        # Create token provider
        token_provider = await create_resource(TokenProviderFactory, self.config.token_provider)

        # Set initial token
        await self._update_auth_header(connector, token_provider)

        # Start background refresh if needed
        self._start_refresh_task(connector, token_provider)

    async def _update_auth_header(self, connector: Any, token_provider: TokenProvider) -> None:
        """Update the connector's auth header with current token."""
        token = await token_provider.get_token()
        auth_header = f"Bearer {token.value}"

        # Use the connector's set_auth_header method if available
        if hasattr(connector, "set_auth_header"):
            getattr(connector, "set_auth_header")(auth_header)
        elif isinstance(connector, dict):
            connector["Authorization"] = auth_header
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

    async def cleanup(self) -> None:
        """Clean up any background tasks or resources."""
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
