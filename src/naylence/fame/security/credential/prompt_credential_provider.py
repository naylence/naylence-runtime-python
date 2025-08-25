from __future__ import annotations

from typing import Optional

from .credential_provider import CredentialProvider


class PromptCredentialProvider(CredentialProvider):
    """
    A credential provider that prompts the user on STDIN for credentials.
    Caches credentials for the session. Good for development.
    """

    def __init__(self, credential_name: str = "credential"):
        """
        Initialize the provider with a specific credential name for prompting.

        Args:
            credential_name: The name to display in the prompt
        """
        self._credential_name = credential_name
        self._cached_value: Optional[str] = None

    async def get(self) -> Optional[str]:
        """Retrieve the credential by prompting the user (with caching)."""
        if self._cached_value is not None:
            return self._cached_value

        try:
            # Simple prompt without echo hiding for now
            # In production, you might want to use getpass
            value = input(f"Enter credential '{self._credential_name}': ").strip()
            if value:
                self._cached_value = value
                return value
            return None
        except (EOFError, KeyboardInterrupt):
            return None
