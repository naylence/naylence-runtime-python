from __future__ import annotations

from abc import ABC
from typing import TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.security.auth.token_verifier import TokenVerifier


class TokenVerifierConfig(ResourceConfig):
    """Base configuration for token verifiers"""

    type: str = "TokenVerifier"


C = TypeVar("C", bound=TokenVerifierConfig)


class TokenVerifierFactory(ABC, ResourceFactory[TokenVerifier, C]): ...
