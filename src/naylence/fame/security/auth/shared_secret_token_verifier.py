from __future__ import annotations

from typing import Any, Dict, Optional

from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.credential import CredentialProvider


class SharedSecretTokenVerifier(TokenVerifier):
    """
    A simple token verifier that validates tokens against a shared secret.

    This implementation performs basic validation by comparing the provided
    token against a secret retrieved from a credential provider.
    """

    def __init__(self, credential_provider: CredentialProvider):
        self._credential_provider = credential_provider

    async def verify(self, token: str, *, expected_audience: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify a token against the shared secret.

        This is a simple implementation that checks if the token matches
        the expected secret. In a real implementation, this might decode
        a JWT or perform more sophisticated validation.
        """
        expected_secret = await self._credential_provider.get()

        if token != expected_secret:
            raise ValueError("Invalid shared secret token")

        # Return expected claims for a valid shared secret token
        claims: Dict[str, Any] = {
            "sub": "*",  # Standard subject claim for shared secret
            "mode": "shared-secret",  # Authentication mode
            "valid": True,
        }
        if expected_audience:
            claims["aud"] = expected_audience

        return claims


# Note: Backward compatibility is maintained by the single class above
