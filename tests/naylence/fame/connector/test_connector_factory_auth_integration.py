"""
Test integration of auth strategies with connector factories.
"""

from unittest.mock import Mock, patch

import pytest

from naylence.fame.connector.http_stateless_connector_factory import (
    HttpStatelessConnectorConfig,
    HttpStatelessConnectorFactory,
)
from naylence.fame.security.auth.auth_config import BearerTokenHeaderAuth
from naylence.fame.security.auth.static_token_provider_factory import StaticTokenProviderConfig


class TestConnectorFactoryAuthIntegration:
    """Test auth strategy integration with connector factories."""

    @pytest.mark.asyncio
    async def test_http_connector_with_bearer_auth(self):
        """Test HttpStatelessConnector factory applies auth strategy."""

        # Create config with auth
        config = HttpStatelessConnectorConfig(
            url="https://example.com/api",
            auth=BearerTokenHeaderAuth(
                token_provider=StaticTokenProviderConfig(
                    token="integration-test-token", type="StaticTokenProvider"
                )
            ),
        )

        factory = HttpStatelessConnectorFactory()

        # Mock the connector's set_auth_header method
        with patch(
            "naylence.fame.connector.http_stateless_connector_factory.HttpStatelessConnector"
        ) as MockConnector:
            mock_connector_instance = Mock()
            mock_connector_instance.set_auth_header = Mock()
            MockConnector.return_value = mock_connector_instance

            # Create connector
            result = await factory.create(config)

            # Verify connector was created
            MockConnector.assert_called_once_with(url="https://example.com/api", max_queue=1024)

            # Verify auth header was set
            mock_connector_instance.set_auth_header.assert_called_once_with("Bearer integration-test-token")

            assert result is mock_connector_instance

    @pytest.mark.asyncio
    async def test_http_connector_without_auth(self):
        """Test HttpStatelessConnector factory works without auth."""

        config = HttpStatelessConnectorConfig(url="https://example.com/api", auth=None)

        factory = HttpStatelessConnectorFactory()

        with patch(
            "naylence.fame.connector.http_stateless_connector_factory.HttpStatelessConnector"
        ) as MockConnector:
            mock_connector_instance = Mock()
            MockConnector.return_value = mock_connector_instance

            # Create connector
            result = await factory.create(config)

            # Verify connector was created
            MockConnector.assert_called_once_with(url="https://example.com/api", max_queue=1024)

            # Verify no auth methods were called
            assert (
                not hasattr(mock_connector_instance, "set_auth_header")
                or not mock_connector_instance.set_auth_header.called
            )

            assert result is mock_connector_instance
