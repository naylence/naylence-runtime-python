from __future__ import annotations

from typing import TypeVar

from pydantic import ConfigDict
from pydantic.alias_generators import to_camel

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.security.auth.token_provider import TokenProvider


class TokenProviderConfig(ResourceConfig):
    """Base configuration for token providers"""

    type: str = "TokenProvider"

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )


C = TypeVar("C", bound=TokenProviderConfig)


class TokenProviderFactory(ResourceFactory[TokenProvider, C]):
    """Factory for creating token providers"""
