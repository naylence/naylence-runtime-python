from __future__ import annotations

from typing import Optional

from .credential_provider import CredentialProvider


class StaticCredentialProvider(CredentialProvider):
    """
    A credential provider that holds a single credential value.
    Good for testing and simple configurations.
    """

    def __init__(self, credential_value: str):
        """
        Initialize the provider with a specific credential value.

        Args:
            credential_value: The credential value to return
        """
        self._credential_value = credential_value

    async def get(self) -> Optional[str]:
        """Retrieve the configured credential value."""
        return self._credential_value
