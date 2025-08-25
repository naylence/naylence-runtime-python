"""Composite load balancing strategy implementation."""

from typing import Any, Optional, Sequence

from naylence.fame.core import FameEnvelope
from naylence.fame.util.logging import getLogger

from .load_balancing_strategy import LoadBalancingStrategy

logger = getLogger(__name__)


class CompositeLoadBalancingStrategy(LoadBalancingStrategy):
    """
    Composite load balancing strategy that chains multiple strategies with fallback.

    Tries each strategy in order until one returns a non-None result.
    This allows for sophisticated routing policies like "sticky first, then HRW fallback".
    """

    def __init__(self, strategies: Sequence[LoadBalancingStrategy]):
        if not strategies:
            raise ValueError("CompositeLoadBalancingStrategy requires at least one strategy")
        self.strategies = list(strategies)

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        """
        Try each strategy in order until one returns a non-None result.

        Args:
            pool_key: The pool identifier
            segments: Available segments in the pool
            envelope: The envelope being routed

        Returns:
            The chosen segment ID from the first successful strategy, or None if all fail
        """
        if not segments:
            return None

        for i, strategy in enumerate(self.strategies):
            try:
                result = strategy.choose(pool_key, segments, envelope)
                if result is not None:
                    logger.debug(
                        "composite_strategy_success",
                        envelope_id=envelope.id,
                        pool_key=pool_key,
                        strategy_index=i,
                        strategy_type=type(strategy).__name__,
                        result=result,
                    )
                    return result
            except Exception as e:
                logger.warning(
                    "composite_strategy_error",
                    envelope_id=envelope.id,
                    pool_key=pool_key,
                    strategy_index=i,
                    strategy_type=type(strategy).__name__,
                    error=str(e),
                )
                # Continue to next strategy on error

        logger.debug(
            "composite_strategy_all_failed",
            envelope_id=envelope.id,
            pool_key=pool_key,
            strategy_count=len(self.strategies),
        )
        return None
