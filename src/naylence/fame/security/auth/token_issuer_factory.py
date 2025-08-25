from __future__ import annotations

from abc import ABC
from typing import TypeVar

from pydantic import ConfigDict

from naylence.fame.core import ResourceConfig, ResourceFactory
from naylence.fame.security.auth.token_issuer import TokenIssuer


class TokenIssuerConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "TokenIssuer"


C = TypeVar("C", bound=TokenIssuerConfig)


class TokenIssuerFactory(ABC, ResourceFactory[TokenIssuer, C]): ...
