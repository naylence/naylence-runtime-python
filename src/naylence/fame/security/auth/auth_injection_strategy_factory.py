"""
Factory system for creating authentication injection strategies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from pydantic import ConfigDict
from pydantic.alias_generators import to_camel

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource

if TYPE_CHECKING:
    from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy


class AuthInjectionStrategyConfig(ResourceConfig):
    """Base class for connector authentication configurations."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,
    )


C = TypeVar("C", bound=AuthInjectionStrategyConfig)


class AuthInjectionStrategyFactory(ResourceFactory):
    """Base factory for creating auth injection strategies."""

    @staticmethod
    async def create_auth_strategy(auth_config: AuthInjectionStrategyConfig) -> AuthInjectionStrategy:
        return await create_resource(AuthInjectionStrategyFactory, auth_config)
