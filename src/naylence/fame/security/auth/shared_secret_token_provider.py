from __future__ import annotations

from datetime import datetime, timedelta, timezone

from naylence.fame.security.credential import CredentialProvider

from .token import Token
from .token_provider import TokenProvider


class SharedSecretTokenProvider(TokenProvider):
    """
    A token provider that retrieves shared secret tokens from a credential provider.
    """

    def __init__(self, credential_provider: CredentialProvider):
        self._credential_provider = credential_provider

    async def get_token(self) -> Token:
        token_value = await self._credential_provider.get()
        # Shared secrets typically don't expire, so use a far future date
        far_future = datetime.now(timezone.utc) + timedelta(days=365 * 100)
        return Token(value=token_value or "", expires_at=far_future)
