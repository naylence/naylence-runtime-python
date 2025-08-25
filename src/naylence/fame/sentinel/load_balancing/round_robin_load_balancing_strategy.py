"""Round robin load balancing strategy implementation."""

from typing import Any, Optional, Sequence

from naylence.fame.core import FameEnvelope

from .load_balancing_strategy import LoadBalancingStrategy


class RoundRobinLoadBalancingStrategy(LoadBalancingStrategy):
    def __init__(self):
        # maintain a counter per key
        self._counters: dict[Any, int] = {}

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        if not segments:
            return None
        idx = self._counters.get(pool_key, 0) % len(segments)
        self._counters[pool_key] = idx + 1
        return segments[idx]
