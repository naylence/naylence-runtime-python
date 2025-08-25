"""HRW (Highest Random Weight) load balancing strategy implementation."""

import hashlib
from typing import Any, Optional, Sequence

from naylence.fame.core import FameEnvelope

from .load_balancing_strategy import LoadBalancingStrategy


class HRWLoadBalancingStrategy(LoadBalancingStrategy):
    def __init__(self, *, hash_func=None, sticky_attr: Optional[str] = None):
        self.hash = hash_func or (lambda s: int(hashlib.sha256(s.encode()).hexdigest(), 16))
        self.sticky_attr = sticky_attr

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        if not segments:
            return None

        # pick salt from sticky_attr if set, else use a random per-envelope salt
        if self.sticky_attr:
            salt = getattr(envelope, self.sticky_attr, None) or envelope.id
        else:
            salt = envelope.id  # random every time → effectively no stickiness

        best = max(segments, key=lambda s: self.hash(f"{s}:{salt}"))
        return best
