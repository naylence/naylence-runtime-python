from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import ConfigDict
from pydantic.alias_generators import to_camel

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource
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

    @classmethod
    async def create_token_provider(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Optional[TokenProvider]:
        """Create a token provider instance based on the provided configuration.

        Args:
            cfg: Configuration for the provider, or None for default

        Returns:
            A TokenProvider instance, or None if creation fails
        """
        return await create_resource(
            TokenProviderFactory,
            cfg,
            **kwargs,
        )
