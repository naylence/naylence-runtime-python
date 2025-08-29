from __future__ import annotations

from abc import ABC
from typing import Optional, TypeVar

from pydantic import ConfigDict

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource, create_resource
from naylence.fame.security.auth.token_issuer import TokenIssuer


class TokenIssuerConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "TokenIssuer"


C = TypeVar("C", bound=TokenIssuerConfig)


class TokenIssuerFactory(ABC, ResourceFactory[TokenIssuer, C]):
    @classmethod
    async def create_token_issuer(cls, config: Optional[C] = None, **kwargs) -> TokenIssuer:
        if config:
            token_issuer = await create_resource(TokenIssuerFactory, config, **kwargs)
            return token_issuer

        token_issuer = await create_default_resource(TokenIssuerFactory, **kwargs)

        assert token_issuer, "Failed to create default TokenIssuer"

        return token_issuer
