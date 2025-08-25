from __future__ import annotations

from typing import Optional

from .credential_provider import CredentialProvider


class NoneCredentialProvider(CredentialProvider):
    """
    A credential provider that returns None for all requests.
    Good for "no-auth" scenarios.
    """

    async def get(self) -> Optional[str]:
        """Always returns None (no credentials)."""
        return None
