"""
Query parameter authentication strategy implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy
from naylence.fame.security.auth.token_provider_factory import TokenProviderFactory

if TYPE_CHECKING:
    from naylence.fame.security.auth.query_param_auth_injection_strategy_factory import (
        QueryParamAuthInjectionStrategyConfig,
    )


class QueryParamAuthInjectionStrategy(AuthInjectionStrategy):
    """Strategy for query parameter authentication."""

    def __init__(self, config: QueryParamAuthInjectionStrategyConfig):
        self.config = config

    async def apply(self, connector: Any) -> None:
        """For query param auth, the token is added to the URL during connection establishment."""
        pass

    async def modify_url(self, url: str) -> str:
        """Modify URL to include auth query parameters."""
        # Create token provider from config
        token_provider = await create_resource(TokenProviderFactory, self.config.token_provider)

        # Get current token and modify URL
        token = await token_provider.get_token()

        parts = urlparse(url)
        query = dict(parse_qsl(parts.query))
        query[self.config.param_name] = token.value
        new_query = urlencode(query)
        return urlunparse(parts._replace(query=new_query))

    async def cleanup(self) -> None:
        """Clean up any background tasks or resources."""
        pass
