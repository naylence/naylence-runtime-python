from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import (
    AuthorizerConfig,
    AuthorizerFactory,
)


class NoopAuthorizerConfig(AuthorizerConfig):
    type: str = "NoopAuthorizer"


class NoopAuthorizerFactory(AuthorizerFactory):
    async def create(
        self,
        config: Optional[NoopAuthorizerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Authorizer:
        # Lazy import to avoid circular dependencies
        from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer

        return NoopAuthorizer()
