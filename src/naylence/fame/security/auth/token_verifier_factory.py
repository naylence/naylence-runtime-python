from __future__ import annotations

from abc import ABC
from typing import Any, Optional, TypeVar

from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
    create_resource,
)
from naylence.fame.security.auth.token_verifier import TokenVerifier

TOKEN_VERIFIER_FACTORY_BASE_TYPE = "TokenVerifierFactory"


class TokenVerifierConfig(ResourceConfig):
    """Base configuration for token verifiers"""

    type: str = "TokenVerifier"


C = TypeVar("C", bound=TokenVerifierConfig)


class TokenVerifierFactory(ABC, ResourceFactory[TokenVerifier, C]):
    @classmethod
    async def create_token_verifier(
        cls,
        config: Optional[C | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenVerifier:
        """
        Create a TokenVerifier instance from configuration or use default.

        Args:
            config: Optional configuration for the token verifier
            **kwargs: Additional arguments passed to the factory

        Returns:
            A TokenVerifier instance

        Raises:
            ValueError: If token verifier creation fails
        """
        if config:
            instance = await create_resource(
                TokenVerifierFactory, config=config, **kwargs
            )

            if not instance:
                raise ValueError("Failed to create token verifier from configuration")

            return instance

        instance = await create_default_resource(TokenVerifierFactory, config=None, **kwargs)

        if not instance:
            raise ValueError("Failed to create default token verifier")

        return instance
