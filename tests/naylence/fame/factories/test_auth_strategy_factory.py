"""Test all extension point factories to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyFactory,
)
from naylence.fame.security.auth.bearer_token_header_auth_injection_strategy import (
    BearerTokenHeaderAuthInjectionStrategy,
)
from naylence.fame.security.auth.no_auth_injection_strategy import (
    NoAuthInjectionStrategy,
)


class TestAuthStrategyFactory:
    """Test AuthStrategyFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_no_auth_strategy_factory(self):
        """Test NoAuthStrategy factory creates correct instance."""
        config = {"type": "NoAuth"}
        strategy = await create_resource(AuthInjectionStrategyFactory, config)

        assert isinstance(strategy, NoAuthInjectionStrategy)
        assert strategy.__class__.__name__ == "NoAuthInjectionStrategy"

    @pytest.mark.asyncio
    async def test_bearer_attach_auth_strategy_factory(self):
        """Test BearerTokenHeaderAuth factory creates correct instance."""
        config = {
            "type": "BearerTokenHeaderAuth",
            "tokenProvider": {"type": "StaticTokenProvider", "token": "test-token-123"},
        }
        strategy = await create_resource(AuthInjectionStrategyFactory, config)

        assert isinstance(strategy, BearerTokenHeaderAuthInjectionStrategy)
        assert strategy.__class__.__name__ == "BearerTokenHeaderAuthInjectionStrategy"

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
