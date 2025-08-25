from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(slots=True, frozen=True)
class Token:
    """
    A token object that encapsulates both the token value and its expiration time.
    """

    value: str
    expires_at: Optional[datetime] = None

    @property
    def is_expired(self) -> bool:
        """Check if the token is expired."""
        return self.expires_at is not None and self.expires_at <= datetime.now(timezone.utc)

    @property
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired)."""
        return not self.is_expired
