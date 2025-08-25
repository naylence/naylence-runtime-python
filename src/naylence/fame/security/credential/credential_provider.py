from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class CredentialProvider(Protocol):
    """Abstract source of runtime credentials (tokens, passwords, secrets)."""

    async def get(self) -> Optional[str]:
        """
        Retrieve the credential value.

        The credential provider already knows which specific credential to retrieve
        based on its configuration (e.g., environment variable name, secret store key).

        Returns:
            The credential value or None if not found
        """
        ...
