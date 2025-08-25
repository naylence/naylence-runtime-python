"""Load balancing strategy protocol."""

from __future__ import annotations

from typing import Any, Optional, Protocol, Sequence, runtime_checkable

from naylence.fame.core import FameEnvelope


@runtime_checkable
class LoadBalancingStrategy(Protocol):
    """
    Strategy for picking one downstream segment from a pool.

    Returns Optional[str] to support fallback chaining - None indicates
    the strategy couldn't make a decision and fallback should be tried.
    """

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]: ...
