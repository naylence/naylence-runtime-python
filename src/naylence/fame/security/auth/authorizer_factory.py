from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource, create_resource
from naylence.fame.security.auth.authorizer import Authorizer


class AuthorizerConfig(ResourceConfig):
    """Base configuration for generic authorizers"""

    type: str = "Authorizer"


C = TypeVar("C", bound=AuthorizerConfig)


class AuthorizerFactory(ResourceFactory[Authorizer, C]):
    """Factory for creating generic authorizers"""

    @classmethod
    async def create_authorizer(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        *,
        token_verifier=None,
        **kwargs,
    ) -> Optional[Authorizer]:
        """Create an Authorizer instance based on the provided configuration."""
        if isinstance(cfg, AuthorizerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        if cfg_dict:
            return await create_resource(AuthorizerFactory, config=cfg_dict, **kwargs)
        authorizer = await create_default_resource(
            AuthorizerFactory, cfg_dict, token_verifier=token_verifier, **kwargs
        )
        return authorizer


class NoopAuthorizerConfig(AuthorizerConfig):
    """Configuration for no-op authorizer that allows all requests"""

    type: str = "NoopAuthorizer"


class NoopAuthorizerFactory(AuthorizerFactory):
    """Factory for creating no-op authorizers"""

    async def create(
        self,
        config: Optional[NoopAuthorizerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Authorizer:
        from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer

        return NoopAuthorizer()
