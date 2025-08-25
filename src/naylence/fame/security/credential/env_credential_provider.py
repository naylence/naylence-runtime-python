from __future__ import annotations

import os
from typing import Optional

from .credential_provider import CredentialProvider


class EnvCredentialProvider(CredentialProvider):
    """
    A credential provider that reads credentials from environment variables.
    """

    def __init__(self, var_name: str):
        """
        Initialize the provider with a specific environment variable name.

        Args:
            var_name: The name of the environment variable to read
        """
        self._var_name = var_name

    async def get(self) -> Optional[str]:
        """Retrieve the credential from the configured environment variable."""
        return os.environ.get(self._var_name)
