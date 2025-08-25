from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class TokenIssuer(Protocol):
    """Issues tokens with claims-based payload."""

    @property
    def issuer(self) -> str:
        """Get the issuer identifier for the tokens."""
        ...

    def issue(self, claims: Dict[str, Any]) -> str:
        """Issue a token with the provided claims."""
        ...
