from __future__ import annotations

from typing import Protocol, runtime_checkable

from naylence.fame.security.auth.token_verifier import TokenVerifier


@runtime_checkable
class TokenVerifierProvider(Protocol):
    """
    Protocol for authorizers that can provide their internal token verifier.

    This allows reusing the same verifier instance that the authorizer uses
    for token validation, avoiding duplicate configuration and setup.
    """

    @property
    def token_verifier(self) -> TokenVerifier:
        """Get the token verifier used by this authorizer."""
        ...
