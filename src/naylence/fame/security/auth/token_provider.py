from __future__ import annotations

from typing import Optional, Protocol, TypeGuard, runtime_checkable

from .auth_identity import AuthIdentity
from .token import Token


@runtime_checkable
class TokenProvider(Protocol):
    """Abstract provider of authentication tokens for node attachment."""

    async def get_token(self) -> Token:
        """
        Get an authentication token for node attachment.

        Returns:
            A Token object containing the token value and expiration
        """
        ...


@runtime_checkable
class IdentityExposingTokenProvider(TokenProvider, Protocol):
    """
    A token provider that can also expose identity information.

    This protocol extends TokenProvider to add the capability of
    extracting identity information from the authentication source,
    typically the subject claim from a JWT token.
    """

    async def get_identity(self) -> Optional[AuthIdentity]:
        """
        Get the identity information from the authentication source.

        Returns:
            An AuthIdentity object if identity can be extracted, None otherwise
        """
        ...


def is_identity_exposing_token_provider(
    candidate: object,
) -> TypeGuard[IdentityExposingTokenProvider]:
    """
    Check if a candidate object is an IdentityExposingTokenProvider.

    Args:
        candidate: The object to check

    Returns:
        True if the candidate implements IdentityExposingTokenProvider protocol
    """
    return (
        isinstance(candidate, TokenProvider)
        and hasattr(candidate, "get_identity")
        and callable(getattr(candidate, "get_identity", None))
    )
