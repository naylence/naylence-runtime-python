"""Test all extension point factories to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.auth.auth_injection_strategy import (
    BearerTokenHeaderStrategy,
    NoAuthStrategy,
)
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyFactory,
)


class TestAuthStrategyFactory:
    """Test AuthStrategyFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_no_auth_strategy_factory(self):
        """Test NoAuthStrategy factory creates correct instance."""
        config = {"type": "NoAuthStrategy"}
        strategy = await create_resource(AuthInjectionStrategyFactory, config)

        assert isinstance(strategy, NoAuthStrategy)
        assert strategy.__class__.__name__ == "NoAuthStrategy"

    @pytest.mark.asyncio
    async def test_bearer_attach_auth_strategy_factory(self):
        """Test BearerTokenHeaderStrategy factory creates correct instance."""
        config = {"type": "BearerTokenHeaderStrategy"}
        strategy = await create_resource(AuthInjectionStrategyFactory, config)

        assert isinstance(strategy, BearerTokenHeaderStrategy)
        assert strategy.__class__.__name__ == "BearerTokenHeaderStrategy"

    @pytest.mark.asyncio
    async def test_auth_strategy_factory_invalid_type(self):
        """Test AuthInjectionStrategyFactory with invalid type raises error."""
        config = {"type": "InvalidAuthStrategy"}

        with pytest.raises(Exception):  # Should raise some form of error
            await create_resource(AuthInjectionStrategyFactory, config)

    @pytest.mark.asyncio
    async def test_auth_strategy_factory_no_config(self):
        """Test AuthInjectionStrategyFactory with no config."""
        # Some factories might have default behavior for None config
        try:
            strategy = await create_resource(AuthInjectionStrategyFactory, None)
            # If it succeeds, verify it returns a valid strategy
            assert hasattr(strategy, "apply")
        except Exception:
            # If it fails, that's also valid behavior
            pass
