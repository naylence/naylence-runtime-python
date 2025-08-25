"""Sticky load balancing strategy implementation."""

from typing import Any, Optional, Sequence

from naylence.fame.core import FameEnvelope
from naylence.fame.stickiness.load_balancer_stickiness_manager import (
    LoadBalancerStickinessManager,
)
from naylence.fame.util.logging import getLogger

from .load_balancing_strategy import LoadBalancingStrategy

logger = getLogger(__name__)


class StickyLoadBalancingStrategy(LoadBalancingStrategy):
    """
    Load balancing strategy that provides session affinity by delegating to a SentinelStickinessManager.

    This strategy delegates all stickiness logic to the configured SentinelStickinessManager:
    1. For inbound envelopes, asks the manager to resolve any sticky associations
       (AFT, SID cache, deterministic SID)
    2. If the manager returns a replica ID, routes to that replica
    3. If no sticky match, returns None to allow composite strategy fallback
    """

    def __init__(self, stickiness_manager: LoadBalancerStickinessManager):
        self.stickiness_manager = stickiness_manager
        self._last_chosen_replica: Optional[str] = None

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        """
        Choose a segment from the pool based on session affinity.

        Args:
            pool_key: The pool identifier
            segments: Available segments in the pool
            envelope: The envelope being routed

        Returns:
            The sticky segment ID if AFT match found, or None to allow fallback
        """
        if not segments:
            return None

        # Ask the stickiness manager to resolve any sticky association (AFT/SID cache/deterministic SID)
        sticky_replica_segment = self.stickiness_manager.get_sticky_replica_segment(envelope, segments)

        if sticky_replica_segment and sticky_replica_segment in segments:
            logger.debug(
                "routing_via_stickiness",
                envelope_id=envelope.id,
                pool_key=pool_key,
                replica_id=sticky_replica_segment,
                aft_present=bool(envelope.aft),
                sid_present=bool(envelope.sid),
            )
            self._last_chosen_replica = sticky_replica_segment
            return sticky_replica_segment

        # No stickiness match - return None to allow composite strategy fallback
        logger.debug(
            "no_stickiness_match_fallback",
            envelope_id=envelope.id,
            pool_key=pool_key,
            aft_present=bool(envelope.aft),
            sid_present=bool(envelope.sid),
        )
        return None

    def get_metrics(self):
        """Get stickiness metrics by delegating to the stickiness manager."""
        return getattr(self.stickiness_manager, "get_metrics", lambda: {})()

    def get_associations(self):
        """Get current AFT associations by delegating to the stickiness manager."""
        return getattr(self.stickiness_manager, "get_associations", lambda: {})()
