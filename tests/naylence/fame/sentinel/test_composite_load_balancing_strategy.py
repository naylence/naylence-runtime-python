"""
Tests for the CompositeLoadBalancingStrategy and enhanced stickiness integration.

This test suite validates:
1. CompositeLoadBalancingStrategy fallback chaining behavior
2. Optional[str] return semantics for all strategies
3. Extension point factory registration
4. Integration with StickyLoadBalancingStrategy
5. Error handling and edge cases
"""

from typing import Any, Optional, Sequence

import pytest

from naylence.fame.core import FameAddress, FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.sentinel.load_balancing.composite_load_balancing_strategy import (
    CompositeLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.composite_load_balancing_strategy_factory import (
    CompositeLoadBalancingStrategyConfig,
    CompositeLoadBalancingStrategyFactory,
)
from naylence.fame.sentinel.load_balancing.hrw_load_balancing_strategy import HRWLoadBalancingStrategy
from naylence.fame.sentinel.load_balancing.hrw_load_balancing_strategy_factory import (
    HRWLoadBalancingStrategyConfig,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import LoadBalancingStrategy
from naylence.fame.sentinel.load_balancing.random_load_balancing_strategy import RandomLoadBalancingStrategy
from naylence.fame.sentinel.load_balancing.random_load_balancing_strategy_factory import (
    RandomLoadBalancingStrategyConfig,
)
from naylence.fame.sentinel.load_balancing.round_robin_load_balancing_strategy import (
    RoundRobinLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.round_robin_load_balancing_strategy_factory import (
    RoundRobinLoadBalancingStrategyConfig,
)
from naylence.fame.sentinel.load_balancing.sticky_load_balancing_strategy import StickyLoadBalancingStrategy
from naylence.fame.sentinel.load_balancing.sticky_load_balancing_strategy_factory import (
    StickyLoadBalancingStrategyConfig,
)
from naylence.fame.stickiness.simple_load_balancer_stickiness_manager import (
    SimpleLoadBalancerStickinessManager,
)
from naylence.fame.stickiness.simple_load_balancer_stickiness_manager_factory import (
    SimpleLoadBalanderStickinessManagerConfig,
)


class AlwaysNoneStrategy(LoadBalancingStrategy):
    """Test strategy that always returns None to verify fallback behavior."""

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        return None


class AlwaysFirstStrategy(LoadBalancingStrategy):
    """Test strategy that always returns the first segment if available."""

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        return segments[0] if segments else None


class AlwaysFailStrategy(LoadBalancingStrategy):
    """Test strategy that always raises an exception."""

    def choose(self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope) -> Optional[str]:
        raise RuntimeError("Intentional test failure")


def create_test_envelope(
    envelope_id: str = "test", aft: Optional[str] = None, sid: Optional[str] = None
) -> FameEnvelope:
    """Create a test envelope."""
    return FameEnvelope(
        id=envelope_id,
        frame=DataFrame(payload="test"),
        to=FameAddress("test@domain/path"),
        aft=aft,
        sid=sid or envelope_id,  # Use envelope_id as SID if not specified
    )


class TestCompositeLoadBalancingStrategy:
    """Test the CompositeLoadBalancingStrategy."""

    def test_single_strategy_success(self):
        """Test composite with single successful strategy."""
        strategy = CompositeLoadBalancingStrategy([AlwaysFirstStrategy()])
        envelope = create_test_envelope()
        segments = ["seg1", "seg2", "seg3"]

        result = strategy.choose("pool", segments, envelope)
        assert result == "seg1"

    def test_fallback_chain(self):
        """Test fallback through multiple strategies."""
        strategies = [
            AlwaysNoneStrategy(),  # Returns None, should fallback
            AlwaysFirstStrategy(),  # Should succeed
            AlwaysNoneStrategy(),  # Should not be reached
        ]
        strategy = CompositeLoadBalancingStrategy(strategies)
        envelope = create_test_envelope()
        segments = ["seg1", "seg2", "seg3"]

        result = strategy.choose("pool", segments, envelope)
        assert result == "seg1"

    def test_all_strategies_fail(self):
        """Test when all strategies return None."""
        strategies = [
            AlwaysNoneStrategy(),
            AlwaysNoneStrategy(),
            AlwaysNoneStrategy(),
        ]
        strategy = CompositeLoadBalancingStrategy(strategies)
        envelope = create_test_envelope()
        segments = ["seg1", "seg2", "seg3"]

        result = strategy.choose("pool", segments, envelope)
        assert result is None

    def test_exception_handling(self):
        """Test that exceptions in strategies are handled gracefully."""
        strategies = [
            AlwaysFailStrategy(),  # Raises exception, should be caught
            AlwaysFirstStrategy(),  # Should succeed after exception
        ]
        strategy = CompositeLoadBalancingStrategy(strategies)
        envelope = create_test_envelope()
        segments = ["seg1", "seg2", "seg3"]

        result = strategy.choose("pool", segments, envelope)
        assert result == "seg1"

    def test_empty_segments(self):
        """Test with empty segments list."""
        strategy = CompositeLoadBalancingStrategy([AlwaysFirstStrategy()])
        envelope = create_test_envelope()

        result = strategy.choose("pool", [], envelope)
        assert result is None

    def test_empty_strategies_raises(self):
        """Test that empty strategies list raises ValueError."""
        with pytest.raises(ValueError, match="at least one strategy"):
            CompositeLoadBalancingStrategy([])


class TestOptionalReturnSemantics:
    """Test that all strategies properly support Optional[str] returns."""

    def test_random_strategy_optional_return(self):
        """Test RandomLoadBalancingStrategy returns None for empty segments."""
        strategy = RandomLoadBalancingStrategy()
        envelope = create_test_envelope()

        result = strategy.choose("pool", [], envelope)
        assert result is None

        result = strategy.choose("pool", ["seg1"], envelope)
        assert result == "seg1"

    def test_round_robin_strategy_optional_return(self):
        """Test RoundRobinLoadBalancingStrategy returns None for empty segments."""
        strategy = RoundRobinLoadBalancingStrategy()
        envelope = create_test_envelope()

        result = strategy.choose("pool", [], envelope)
        assert result is None

        result = strategy.choose("pool", ["seg1", "seg2"], envelope)
        assert result in ["seg1", "seg2"]

    def test_hrw_strategy_optional_return(self):
        """Test HRWLoadBalancingStrategy returns None for empty segments."""
        strategy = HRWLoadBalancingStrategy()
        envelope = create_test_envelope()

        result = strategy.choose("pool", [], envelope)
        assert result is None

        result = strategy.choose("pool", ["seg1", "seg2"], envelope)
        assert result in ["seg1", "seg2"]


@pytest.mark.asyncio
class TestCompositeStrategyFactory:
    """Test the CompositeLoadBalancingStrategyFactory."""

    async def test_factory_create_simple(self):
        """Test factory creation with simple strategy configs."""
        config = CompositeLoadBalancingStrategyConfig(
            strategies=[
                RandomLoadBalancingStrategyConfig(),
                HRWLoadBalancingStrategyConfig(),
            ]
        )

        factory = CompositeLoadBalancingStrategyFactory()
        strategy = await factory.create(config)

        assert isinstance(strategy, CompositeLoadBalancingStrategy)
        assert len(strategy.strategies) == 2
        assert isinstance(strategy.strategies[0], RandomLoadBalancingStrategy)
        assert isinstance(strategy.strategies[1], HRWLoadBalancingStrategy)

    async def test_factory_create_with_sticky(self):
        """Test factory creation with sticky strategy."""
        # Create a simple stickiness manager for testing
        stickiness_manager = SimpleLoadBalancerStickinessManager(
            SimpleLoadBalanderStickinessManagerConfig()
        )

        config = CompositeLoadBalancingStrategyConfig(
            strategies=[
                StickyLoadBalancingStrategyConfig(),
                RandomLoadBalancingStrategyConfig(),
            ]
        )

        factory = CompositeLoadBalancingStrategyFactory()
        strategy = await factory.create(
            config, key_provider=get_key_provider(), stickiness_manager=stickiness_manager
        )

        assert isinstance(strategy, CompositeLoadBalancingStrategy)
        assert len(strategy.strategies) == 2
        assert isinstance(strategy.strategies[0], StickyLoadBalancingStrategy)
        assert isinstance(strategy.strategies[1], RandomLoadBalancingStrategy)

    async def test_factory_create_nested_composite(self):
        """Test factory creation with nested composite strategies."""
        config = CompositeLoadBalancingStrategyConfig(
            strategies=[
                CompositeLoadBalancingStrategyConfig(
                    strategies=[
                        RandomLoadBalancingStrategyConfig(),
                        HRWLoadBalancingStrategyConfig(),
                    ]
                ),
                RoundRobinLoadBalancingStrategyConfig(),
            ]
        )

        factory = CompositeLoadBalancingStrategyFactory()
        strategy = await factory.create(config)

        assert isinstance(strategy, CompositeLoadBalancingStrategy)
        assert len(strategy.strategies) == 2
        assert isinstance(strategy.strategies[0], CompositeLoadBalancingStrategy)
        assert isinstance(strategy.strategies[1], RoundRobinLoadBalancingStrategy)

    async def test_factory_create_empty_config_raises(self):
        """Test that empty configuration raises ValueError."""
        config = CompositeLoadBalancingStrategyConfig(strategies=[])
        factory = CompositeLoadBalancingStrategyFactory()

        with pytest.raises(ValueError, match="at least one strategy"):
            await factory.create(config)

    async def test_factory_create_none_config_raises(self):
        """Test that None configuration raises ValueError."""
        factory = CompositeLoadBalancingStrategyFactory()

        with pytest.raises(ValueError, match="at least one strategy"):
            await factory.create(None)


@pytest.mark.asyncio
class TestStickyCompositeIntegration:
    """Test integration between StickyLoadBalancingStrategy and CompositeLoadBalancingStrategy."""

    async def test_sticky_with_fallback(self):
        """Test sticky strategy with fallback in composite."""
        # Create a simple stickiness manager for testing
        stickiness_manager = SimpleLoadBalancerStickinessManager(
            SimpleLoadBalanderStickinessManagerConfig()
        )

        # Create composite: sticky -> random fallback
        config = CompositeLoadBalancingStrategyConfig(
            strategies=[
                StickyLoadBalancingStrategyConfig(),
                RandomLoadBalancingStrategyConfig(),
            ]
        )

        factory = CompositeLoadBalancingStrategyFactory()
        strategy = await factory.create(
            config, key_provider=get_key_provider(), stickiness_manager=stickiness_manager
        )

        pool_key = "test_pool"
        segments = ["replica1", "replica2", "replica3"]

        # First choice - should go through sticky strategy using SID-based routing
        envelope1 = create_test_envelope("session1")
        result1 = strategy.choose(pool_key, segments, envelope1)
        assert result1 in segments

        # Get the sticky strategy
        sticky_strategy = strategy.strategies[0]
        assert isinstance(sticky_strategy, StickyLoadBalancingStrategy)

        # Second request with same SID should be deterministically routed to same segment
        envelope2 = create_test_envelope("session1")  # Same SID
        result2 = strategy.choose(pool_key, segments, envelope2)
        assert result2 == result1  # Should be deterministically consistent

        # Third request with different SID may go to different segment (but still deterministic)
        envelope3 = create_test_envelope("different_session")
        result3 = strategy.choose(pool_key, segments, envelope3)
        assert result3 in segments  # Should be valid segment

        # Same SID as third request should go to same segment
        envelope4 = create_test_envelope("different_session")  # Same SID as envelope3
        result4 = strategy.choose(pool_key, segments, envelope4)
        assert result4 == result3  # Should be deterministically consistent

    async def test_sticky_fallback_on_invalid_aft(self):
        """Test that invalid AFT falls back to next strategy in composite."""

        # Create a custom strategy that always returns None as delegate
        class AlwaysNoneDelegate(LoadBalancingStrategy):
            def choose(
                self, pool_key: Any, segments: Sequence[str], envelope: FameEnvelope
            ) -> Optional[str]:
                return None

        # We'll test this directly without using the factory for this edge case
        sticky_strategy = StickyLoadBalancingStrategy(
            stickiness_manager=SimpleLoadBalancerStickinessManager(
                SimpleLoadBalanderStickinessManagerConfig()
            )
        )

        fallback_strategy = AlwaysFirstStrategy()
        strategy = CompositeLoadBalancingStrategy([sticky_strategy, fallback_strategy])

        pool_key = "test_pool"
        segments = ["replica1", "replica2", "replica3"]

        # Request with invalid AFT should fallback to second strategy
        envelope = create_test_envelope("test", aft="invalid-aft-token")
        result = strategy.choose(pool_key, segments, envelope)
        assert result == "replica1"  # From AlwaysFirstStrategy


if __name__ == "__main__":
    pytest.main([__file__])
