"""
Integration test for WebSocket connector factory auth strategy integration.
Tests that the new auth strategy system works correctly with WebSocket connectors.
"""

from unittest.mock import AsyncMock

import pytest

from naylence.fame.connector.websocket_connector_factory import (
    WebSocketConnectorConfig,
    WebSocketConnectorFactory,
)
from naylence.fame.security.auth.bearer_token_header_auth_injection_strategy_factory import (
    BearerTokenHeaderAuthInjectionStrategyConfig,
)
from naylence.fame.security.auth.no_auth_injection_strategy_factory import (
    NoAuthInjectionStrategyConfig,
)
from naylence.fame.security.auth.static_token_provider_factory import (
    StaticTokenProviderConfig,
)


class MockWebSocket:
    """Mock WebSocket for testing."""

    def __init__(self, url, subprotocols=None, headers=None):
        self.url = url
        self.subprotocols = subprotocols
        self.headers = headers


@pytest.mark.asyncio
async def test_websocket_factory_with_no_auth():
    """Test WebSocket connector factory with no auth."""
    factory = WebSocketConnectorFactory()

    config = WebSocketConnectorConfig(
        url="ws://example.com/ws/downstream", auth=NoAuthInjectionStrategyConfig()
    )

    # Mock the client factory
    mock_websocket = MockWebSocket("ws://example.com/ws/downstream")
    factory._client_factory = AsyncMock(return_value=mock_websocket)

    # Create connector
    connector = await factory.create(config)

    # Verify connector was created
    assert connector is not None

    # Verify client factory was called with correct parameters
    factory._client_factory.assert_called_once_with("ws://example.com/ws/downstream", None, None)


@pytest.mark.asyncio
async def test_websocket_factory_with_bearer_token_auth():
    """Test WebSocket connector factory with bearer token header auth."""
    factory = WebSocketConnectorFactory()

    config = WebSocketConnectorConfig(
        url="ws://example.com/ws/downstream",
        auth=BearerTokenHeaderAuthInjectionStrategyConfig(
            token_provider=StaticTokenProviderConfig(token="test-token-123")
        ),
    )

    # Mock the client factory
    mock_websocket = MockWebSocket("ws://example.com/ws/downstream")
    factory._client_factory = AsyncMock(return_value=mock_websocket)

    # Create connector
    connector = await factory.create(config)

    # Verify connector was created
    assert connector is not None

    # Verify client factory was called
    factory._client_factory.assert_called_once()

    # Verify auth strategy was applied (bearer token should be set via headers or connector method)
    # The exact verification depends on how the auth is applied to the connector


@pytest.mark.asyncio
async def test_websocket_factory_error_handling():
    """Test WebSocket connector factory error handling."""
    factory = WebSocketConnectorFactory()

    # Test with missing config
    with pytest.raises(ValueError, match="Config not set"):
        await factory.create(None)

    # Test invalid configuration
    config = WebSocketConnectorConfig()  # No URL provided
    with pytest.raises(ValueError, match="WebSocket URL must be provided in config"):
        await factory.create(config)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
