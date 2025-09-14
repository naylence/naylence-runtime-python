from __future__ import annotations

from typing import Any

from naylence.fame.security.auth.token_issuer import TokenIssuer


class NoopTokenIssuer(TokenIssuer):
    """
    A no-op TokenIssuer that issues an empty token.

    This is a compatibility wrapper that maintains the old TokenIssuer interface
    while using the new generic noop token issuer implementation.
    """

    def __init__(self):
        pass

    def issue(
        self,
        claims: dict[str, Any],
    ) -> str:
        return ""

    @property
    def issuer(self) -> str:
        """Get the issuer identifier for the tokens."""
        return ""
