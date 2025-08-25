"""Compatibility shims for legacy imports.

This module re-exports load balancing strategy classes from the
`naylence.fame.sentinel.load_balancing` package to preserve backward
compatibility with older tests and code that import from
`naylence.fame.sentinel.load_balancing_strategy`.
"""

from __future__ import annotations

from naylence.fame.sentinel.load_balancing.composite_load_balancing_strategy import (  # noqa: F401
    CompositeLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.hrw_load_balancing_strategy import (  # noqa: F401
    HRWLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (  # noqa: F401
    LoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.random_load_balancing_strategy import (  # noqa: F401
    RandomLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.round_robin_load_balancing_strategy import (  # noqa: F401
    RoundRobinLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.sticky_load_balancing_strategy import (  # noqa: F401
    StickyLoadBalancingStrategy,
)

__all__ = [
    "LoadBalancingStrategy",
    "CompositeLoadBalancingStrategy",
    "RandomLoadBalancingStrategy",
    "RoundRobinLoadBalancingStrategy",
    "HRWLoadBalancingStrategy",
    "StickyLoadBalancingStrategy",
]
