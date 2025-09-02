from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import (
    AuthorizerConfig,
    AuthorizerFactory,
)
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_factory import TokenVerifierConfig


class DefaultAuthorizerConfig(AuthorizerConfig):
    type: str = "DefaultAuthorizer"

    verifier: Optional[TokenVerifierConfig] = Field(
        default=None, description="Configuration for the underlying token verifier"
    )


class DefaultAuthorizerFactory(AuthorizerFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultAuthorizerConfig | dict[str, Any]] = None,
        token_verifier: Optional[TokenVerifier] = None,
        **kwargs: Any,
    ) -> Authorizer:
        if token_verifier is None:
            if not config:
                raise ValueError("Config is not set")

            from naylence.fame.security.auth.token_verifier_factory import (
                TokenVerifierFactory,
            )

            if isinstance(config, dict):
                config = DefaultAuthorizerConfig(**config)

            token_verifier = await create_resource(TokenVerifierFactory, config.verifier)

        # Lazy import to avoid circular dependencies
        from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer

        return DefaultAuthorizer(token_verifier)
