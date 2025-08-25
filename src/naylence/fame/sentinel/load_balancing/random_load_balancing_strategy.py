"""Random load balancing strategy implementation."""

import random
from typing import Any, Optional, Sequence

from naylence.fame.core import FameEnvelope

from .load_balancing_strategy import LoadBalancingStrategy


class RandomLoadBalancingStrategy(LoadBalancingStrategy):
    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        return random.choice(segments) if segments else None
