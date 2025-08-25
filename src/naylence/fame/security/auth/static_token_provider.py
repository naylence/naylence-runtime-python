"""
Static token provider that returns a pre-configured token.
"""

from datetime import datetime
from typing import Optional

from naylence.fame.security.auth.token import Token
from naylence.fame.security.auth.token_provider import TokenProvider


class StaticTokenProvider(TokenProvider):
    """
    Token provider that returns a static, pre-configured token.

    Useful for scenarios where:
    - Token is already known at configuration time
    - Need to inject a specific token for callbacks
    - Testing scenarios with fixed tokens
    """

    def __init__(self, token: str, expires_at: Optional[datetime] = None):
        """
        Initialize with a static token.

        Args:
            token: The static token value
            expires_at: Optional expiration time
        """
        self._token = token
        self._expires_at = expires_at

    async def get_token(self) -> Token:
        """Return the static token."""
        return Token(value=self._token, expires_at=self._expires_at)
