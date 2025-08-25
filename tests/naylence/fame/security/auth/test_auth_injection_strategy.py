"""
Test the auth injection strategy system.
"""

from unittest.mock import Mock

import pytest

from naylence.fame.security.auth.auth_config import BearerTokenHeaderAuth, NoAuth
from naylence.fame.security.auth.auth_injection_strategy import (
    BearerTokenHeaderStrategy,
    NoAuthStrategy,
)
from naylence.fame.security.auth.auth_injection_strategy_factory import create_auth_strategy
from naylence.fame.security.auth.static_token_provider_factory import StaticTokenProviderConfig


class TestAuthInjectionStrategy:
    """Test auth injection strategies."""

    @pytest.mark.asyncio
    async def test_no_auth_strategy(self):
        """Test NoAuthStrategy does nothing."""
        mock_connector = Mock()
        no_auth = NoAuth()

        strategy = await create_auth_strategy(no_auth)
        assert isinstance(strategy, NoAuthStrategy)

        # Should not raise any errors
        await strategy.apply(mock_connector)

        # Should not have called anything on the connector
        assert not hasattr(mock_connector, "set_auth_header") or not mock_connector.set_auth_header.called

    @pytest.mark.asyncio
    async def test_bearer_token_header_strategy(self):
        """Test BearerTokenHeaderStrategy sets auth header."""
        # Create mock connector with set_auth_header method
        mock_connector = Mock()
        mock_connector.set_auth_header = Mock()

        # Create auth config with static token provider
        auth_config = BearerTokenHeaderAuth(
            token_provider=StaticTokenProviderConfig(token="test-token-123", type="StaticTokenProvider")
        )

        strategy = await create_auth_strategy(auth_config)
        assert isinstance(strategy, BearerTokenHeaderStrategy)

        # Apply strategy
        await strategy.apply(mock_connector)

        # Verify auth header was set
        mock_connector.set_auth_header.assert_called_once_with("Bearer test-token-123")

    @pytest.mark.asyncio
    async def test_create_auth_strategy_invalid_type(self):
        """Test create_auth_strategy raises error for unknown types."""

        class UnknownAuth:
            pass

        unknown_auth = UnknownAuth()

        with pytest.raises(ValueError, match="No auth injection strategy factory"):
            await create_auth_strategy(unknown_auth)

    @pytest.mark.asyncio
    async def test_strategy_cleanup(self):
        """Test strategy cleanup cancels background tasks."""
        auth_config = BearerTokenHeaderAuth(
            token_provider=StaticTokenProviderConfig(token="test-token-123", type="StaticTokenProvider")
        )

        strategy = await create_auth_strategy(auth_config)

        # Apply strategy to a mock connector to create the refresh task
        mock_connector = Mock()
        mock_connector.set_auth_header = Mock()
        await strategy.apply(mock_connector)

        # Verify a refresh task was created
        assert strategy._refresh_task is not None
        assert not strategy._refresh_task.done()

        # Store reference to the original task to check later
        original_task = strategy._refresh_task

        await strategy.cleanup()

        # Verify task was cancelled
        assert original_task.cancelled() or original_task.done()
