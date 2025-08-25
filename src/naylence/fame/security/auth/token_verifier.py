from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class TokenVerifier(Protocol):
    """
    Validates tokens and returns decoded claims.
    Used by Fame routers.
    """

    async def verify(self, token: str, *, expected_audience: Optional[str] = None) -> Dict[str, Any]: ...
