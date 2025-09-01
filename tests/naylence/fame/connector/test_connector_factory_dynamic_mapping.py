"""Test ConnectorFactory dynamic mapping functionality."""

from unittest.mock import Mock, patch

import pytest

from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorFactory
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorFactory
from naylence.fame.grants.connection_grant import ConnectionGrant
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant


class TestConnectorFactoryDynamicMapping:
    """Test ConnectorFactory dynamic mapping functionality."""

    def test_websocket_factory_supported_grant_types(self):
        """Test WebSocketConnectorFactory.supported_grant_types() class method."""
        grant_types = WebSocketConnectorFactory.supported_grant_types()

        assert isinstance(grant_types, list)
        assert "WebSocketConnectionGrant" in grant_types
        assert "WebSocketConnector" in grant_types  # Legacy support
        assert len(grant_types) >= 2

    def test_http_factory_supported_grant_types(self):
        """Test HttpStatelessConnectorFactory.supported_grant_types() class method."""
        grant_types = HttpStatelessConnectorFactory.supported_grant_types()

        assert isinstance(grant_types, list)
        assert "HttpConnectionGrant" in grant_types
        assert "HttpStatelessConnector" in grant_types  # Legacy support
        assert len(grant_types) >= 2

    def test_websocket_factory_config_from_grant(self):
        """Test WebSocketConnectorFactory.config_from_grant() class method."""
        grant = WebSocketConnectionGrant(
            type="WebSocketConnectionGrant", purpose="node.attach", url="wss://example.com/test", auth=None
        )

        config = WebSocketConnectorFactory.config_from_grant(grant)

        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        assert isinstance(config, WebSocketConnectorConfig)
        assert config.type == "WebSocketConnector"
        assert config.url == "wss://example.com/test"
        assert config.auth is None

    def test_http_factory_config_from_grant(self):
        """Test HttpStatelessConnectorFactory.config_from_grant() class method."""
        grant = HttpConnectionGrant(
            type="HttpConnectionGrant", purpose="node.attach", url="https://example.com/test", auth=None
        )

        config = HttpStatelessConnectorFactory.config_from_grant(grant)

        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        assert isinstance(config, HttpStatelessConnectorConfig)
        assert config.type == "HttpStatelessConnector"
        assert config.url == "https://example.com/test"
        assert config.auth is None

    @pytest.mark.asyncio
    async def test_websocket_factory_create_connector_using_config_from_grant(self):
        """Test WebSocketConnectorFactory by converting grant to config and creating connector."""
        factory = WebSocketConnectorFactory()
        grant = WebSocketConnectionGrant(
            type="WebSocketConnectionGrant", purpose="node.attach", url="ws://example.com/test", auth=None
        )

        # Convert grant to config
        config = factory.config_from_grant(grant)

        # Mock the websocket connection to avoid actual network calls
        with patch.object(factory, "_client_factory") as mock_client_factory:
            mock_websocket = Mock()
            mock_client_factory.return_value = mock_websocket

            connector = await factory.create(config, system_id="test-system")

            assert isinstance(connector, WebSocketConnector)
            mock_client_factory.assert_called_once()

    @pytest.mark.asyncio
    async def test_http_factory_create_connector_using_config_from_grant(self):
        """Test HttpStatelessConnectorFactory by converting grant to config and creating connector."""
        factory = HttpStatelessConnectorFactory()
        grant = HttpConnectionGrant(
            type="HttpConnectionGrant", purpose="node.attach", url="https://example.com/test", auth=None
        )

        # Convert grant to config
        config = factory.config_from_grant(grant)

        connector = await factory.create(config, system_id="test-system")

        assert isinstance(connector, HttpStatelessConnector)

    def test_websocket_factory_config_from_grant_invalid_type(self):
        """Test WebSocketConnectorFactory rejects unsupported grant types."""
        grant = HttpConnectionGrant(  # Wrong grant type for WebSocket factory
            type="HttpConnectionGrant", purpose="node.attach", url="https://example.com/test", auth=None
        )

        with pytest.raises(
            ValueError, match="WebSocketConnectorFactory only supports WebSocketConnectionGrant"
        ):
            WebSocketConnectorFactory.config_from_grant(grant)

    def test_http_factory_config_from_grant_invalid_type(self):
        """Test HttpStatelessConnectorFactory rejects unsupported grant types."""
        grant = WebSocketConnectionGrant(  # Wrong grant type for HTTP factory
            type="WebSocketConnectionGrant", purpose="node.attach", url="wss://example.com/test", auth=None
        )

        with pytest.raises(
            ValueError, match="HttpStatelessConnectorFactory only supports HttpConnectionGrant"
        ):
            HttpStatelessConnectorFactory.config_from_grant(grant)

    @pytest.mark.asyncio
    @patch("websockets.connect")
    async def test_dynamic_connector_creation_websocket_grant_dict(self, mock_connect):
        """Test ConnectorFactory.create_connector() with WebSocket grant dict."""

        # Mock the websocket connection
        async def mock_websockets_connect(url, **kwargs):
            mock_ws = Mock()
            mock_ws.send = Mock()
            mock_ws.recv = Mock()
            return mock_ws

        mock_connect.side_effect = mock_websockets_connect

        grant_dict = {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "wss://example.com/test",
            "auth": None,
        }

        # This should work with the real implementation
        connector = await ConnectorFactory.create_connector(grant_dict)
        assert isinstance(connector, WebSocketConnector)

    @pytest.mark.asyncio
    async def test_dynamic_connector_creation_http_grant_dict(self):
        """Test ConnectorFactory.create_connector() with HTTP grant dict."""
        grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "https://example.com/test",
            "auth": None,
        }

        # This should work with the real implementation
        connector = await ConnectorFactory.create_connector(grant_dict)
        assert isinstance(connector, HttpStatelessConnector)

    @pytest.mark.asyncio
    async def test_dynamic_connector_creation_unknown_grant_type(self):
        """Test ConnectorFactory.create_connector() with unknown grant type."""
        grant_dict = {
            "type": "UnknownGrantType",
            "purpose": "node.attach",
            "url": "https://example.com/test",
        }

        with pytest.raises(ValueError, match="No suitable connector configuration found"):
            await ConnectorFactory.create_connector(grant_dict)

    @pytest.mark.asyncio
    async def test_dynamic_connector_creation_connector_config_dict(self):
        """Test ConnectorFactory.create_connector() falls back to connector config for non-grant types."""
        config_dict = {
            "type": "WebSocketConnector",  # This is a connector type, not a grant type
            "url": "ws://example.com/test",
        }

        # This should treat it as a connector config and try to create resource
        # It will fail because it's not a proper ConnectorConfig, but that's expected
        with pytest.raises(Exception):  # Expect some validation error
            await ConnectorFactory.create_connector(config_dict)

    @pytest.mark.asyncio
    @patch("websockets.connect")
    async def test_dynamic_connector_creation_with_connection_grant_object(self, mock_connect):
        """Test ConnectorFactory.create_connector() with ConnectionGrant object directly."""

        # Mock the websocket connection
        async def mock_websockets_connect(url, **kwargs):
            mock_ws = Mock()
            mock_ws.send = Mock()
            mock_ws.recv = Mock()
            return mock_ws

        mock_connect.side_effect = mock_websockets_connect

        grant = WebSocketConnectionGrant(
            type="WebSocketConnectionGrant", purpose="node.attach", url="ws://example.com/test", auth=None
        )

        connector = await ConnectorFactory.create_connector(grant)
        assert isinstance(connector, WebSocketConnector)

    def test_dynamic_connector_creation_missing_type_field(self):
        """Test ConnectorFactory.create_connector() with missing type field."""
        config_dict = {
            "url": "ws://example.com/test"
            # Missing "type" field
        }

        with pytest.raises(ValueError, match="Missing 'type' field in configuration"):
            import asyncio

            asyncio.run(ConnectorFactory.create_connector(config_dict))

    @pytest.mark.asyncio
    async def test_dynamic_connector_creation_no_suitable_factory(self):
        """Test ConnectorFactory.create_connector() when no factory supports the grant type."""
        grant = Mock(spec=ConnectionGrant)
        grant.type = "UnsupportedGrantType"

        with pytest.raises(ValueError, match="No suitable connector configuration found"):
            await ConnectorFactory.create_connector(grant)

    @pytest.mark.asyncio
    async def test_dynamic_connector_creation_multiple_suitable_factories(self):
        """Test ConnectorFactory.create_connector() when multiple factories support the same grant type."""
        # This test is hard to trigger with the current implementation since we have
        # known factory names. For now, just test that the code doesn't crash.
        grant = Mock(spec=ConnectionGrant)
        grant.type = "WebSocketConnectionGrant"  # Use a real grant type

        # With the current implementation, this should work fine
        # (though it will fail due to missing purpose field)
        with pytest.raises(Exception):  # May fail for various validation reasons
            await ConnectorFactory.create_connector(grant)

    def test_invalid_config_or_grant_type(self):
        """Test ConnectorFactory.create_connector() with invalid input type."""
        invalid_input = "not_a_dict_or_grant_or_config"

        with pytest.raises(ValueError, match="Missing 'type' field in configuration"):
            import asyncio

            asyncio.run(ConnectorFactory.create_connector(invalid_input))
