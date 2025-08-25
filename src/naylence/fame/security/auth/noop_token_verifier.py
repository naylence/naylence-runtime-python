from __future__ import annotations

from typing import Any, Dict, Optional

from naylence.fame.security.auth.token_verifier import TokenVerifier


class NoopTokenVerifier(TokenVerifier):
    """
    A no-op TokenVerifier that always approves tokens with empty claims.

    Useful for testing and development environments where authentication
    is not required.
    """

    async def verify(self, token: str, *, expected_audience: Optional[str] = None) -> Dict[str, Any]:
        """Always return empty claims without validating the token."""
        return {}
