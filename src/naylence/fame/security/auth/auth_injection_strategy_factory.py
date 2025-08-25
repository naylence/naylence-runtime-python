"""
Factory system for creating authentication injection strategies.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.core import ResourceConfig, ResourceFactory
from naylence.fame.security.auth.auth_config import (
    BearerTokenHeaderAuth,
    ConnectorAuth,
    NoAuth,
    QueryParamAuth,
    WebSocketSubprotocolAuth,
)
from naylence.fame.security.auth.auth_injection_strategy import (
    AuthInjectionStrategy,
    BearerTokenHeaderStrategy,
    NoAuthStrategy,
    QueryParamStrategy,
    WebSocketSubprotocolStrategy,
)


class AuthInjectionStrategyConfig(ResourceConfig):
    """Base configuration for auth injection strategies."""

    type: str = "AuthInjectionStrategy"


C = TypeVar("C", bound=AuthInjectionStrategyConfig)


class AuthInjectionStrategyFactory(ResourceFactory[AuthInjectionStrategy, C]):
    """Base factory for creating auth injection strategies."""

    pass


class NoAuthStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for NoAuthStrategy."""

    async def create(
        self, config: Optional[NoAuth | dict[str, Any]] = None, **kwargs: Any
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = NoAuth(**config)

        if not config:
            config = NoAuth()

        return NoAuthStrategy(config)


class BearerTokenHeaderStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for BearerTokenHeaderStrategy."""

    async def create(
        self,
        config: Optional[BearerTokenHeaderAuth | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = BearerTokenHeaderAuth.model_validate(config)

        if not config:
            raise ValueError("BearerTokenHeaderAuth config is required")

        return BearerTokenHeaderStrategy(config)


class WebSocketSubprotocolStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for WebSocketSubprotocolStrategy."""

    async def create(
        self,
        config: Optional[WebSocketSubprotocolAuth | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = WebSocketSubprotocolAuth.model_validate(config)

        if not config:
            raise ValueError("WebSocketSubprotocolAuth config is required")

        return WebSocketSubprotocolStrategy(config)


class QueryParamStrategyFactory(AuthInjectionStrategyFactory):
    """Factory for QueryParamStrategy."""

    async def create(
        self, config: Optional[QueryParamAuth | dict[str, Any]] = None, **kwargs: Any
    ) -> AuthInjectionStrategy:
        if isinstance(config, dict):
            config = QueryParamAuth.model_validate(config)

        if not config:
            raise ValueError("QueryParamAuth config is required")

        return QueryParamStrategy(config)


# Registry mapping ConnectorAuth types to their strategy factories
STRATEGY_FACTORY_REGISTRY: dict[type[ConnectorAuth], type[AuthInjectionStrategyFactory]] = {
    NoAuth: NoAuthStrategyFactory,
    BearerTokenHeaderAuth: BearerTokenHeaderStrategyFactory,
    WebSocketSubprotocolAuth: WebSocketSubprotocolStrategyFactory,
    QueryParamAuth: QueryParamStrategyFactory,
}


async def create_auth_strategy(auth_config: ConnectorAuth) -> AuthInjectionStrategy:
    """
    Create an auth injection strategy for the given auth config.

    Args:
        auth_config: The connector auth configuration

    Returns:
        An auth injection strategy instance

    Raises:
        ValueError: If no strategy factory is found for the auth config type
    """
    factory_class = STRATEGY_FACTORY_REGISTRY.get(type(auth_config))
    if not factory_class:
        raise ValueError(f"No auth injection strategy factory for {type(auth_config).__name__}")

    factory = factory_class()
    return await factory.create(auth_config)
