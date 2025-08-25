from __future__ import annotations

from typing import Protocol, runtime_checkable

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
