from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .token import Token
from .token_provider import TokenProvider


class NoneTokenProvider(TokenProvider):
    """
    A token provider that returns an empty token (no authentication).
    Good for "no-auth" scenarios.
    """

    async def get_token(self) -> Token:
        # Return a token with empty value and a far future expiration
        far_future = datetime.now(timezone.utc) + timedelta(days=365 * 100)
        return Token(value="", expires_at=far_future)
