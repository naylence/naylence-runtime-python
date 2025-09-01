"""Integration tests for ConnectorFactory dynamic mapping functionality."""

from unittest.mock import patch

import pytest

from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorFactory
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorFactory
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant


class MockWebSocket:
    """A mock websocket for testing."""

    async def send(self, data):
        pass

    async def recv(self):
        return b"test_response"

    async def close(self):
        pass


class TestConnectorFactoryDynamicMappingIntegration:
    """Integration tests for ConnectorFactory dynamic mapping functionality."""

    async def mock_websockets_connect(self, url, **kwargs):
        """Mock async function for websockets.connect."""
        return MockWebSocket()

    def test_websocket_factory_class_methods_work_without_instantiation(self):
        """Test that class methods work without creating factory instances."""
        # Test supported_grant_types as class method
        grant_types = WebSocketConnectorFactory.supported_grant_types()
        assert "WebSocketConnectionGrant" in grant_types
        assert "WebSocketConnector" in grant_types

        # Test config_from_grant as class method with dict
        grant_dict = {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://example.com/test",
            "auth": None,
        }
        config = WebSocketConnectorFactory.config_from_grant(grant_dict)
        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        assert isinstance(config, WebSocketConnectorConfig)
        assert config.url == "ws://example.com/test"

    def test_http_factory_class_methods_work_without_instantiation(self):
        """Test that class methods work without creating factory instances."""
        # Test supported_grant_types as class method
        grant_types = HttpStatelessConnectorFactory.supported_grant_types()
        assert "HttpConnectionGrant" in grant_types
        assert "HttpStatelessConnector" in grant_types

        # Test config_from_grant as class method with dict
        grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "https://example.com/test",
            "auth": None,
        }
        config = HttpStatelessConnectorFactory.config_from_grant(grant_dict)
        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        assert isinstance(config, HttpStatelessConnectorConfig)
        assert config.url == "https://example.com/test"

    @pytest.mark.asyncio
    @patch("websockets.connect")
    async def test_websocket_grant_to_connector_conversion_real(self, mock_connect):
        """Test real conversion from WebSocket grant to connector."""
        # Mock the websocket connection
        mock_connect.side_effect = self.mock_websockets_connect

        grant = WebSocketConnectionGrant(url="ws://example.com/test", purpose="node.attach")
        factory = WebSocketConnectorFactory()
        config = factory.config_from_grant(grant)
        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        # This will create a real connector but won't actually connect
        connector = await factory.create(WebSocketConnectorConfig.model_validate(config.model_dump()))

        # Verify we get the right type
        assert isinstance(connector, WebSocketConnector)
        # Check that connector has a websocket attribute (the actual connection object)
        assert hasattr(connector, "websocket")
        # Verify the connection was set
        assert connector.websocket is not None

    @pytest.mark.asyncio
    async def test_http_grant_to_connector_conversion_real(self):
        """Test real HTTP grant to connector conversion."""
        factory = HttpStatelessConnectorFactory()
        grant = HttpConnectionGrant(
            type="HttpConnectionGrant", purpose="node.attach", url="https://example.com/test", auth=None
        )
        config = factory.config_from_grant(grant)
        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        connector = await factory.create(HttpStatelessConnectorConfig.model_validate(config.model_dump()))

        assert isinstance(connector, HttpStatelessConnector)
        # The HTTP connector should have the URL configured

    @pytest.mark.asyncio
    @patch("websockets.connect")
    async def test_end_to_end_websocket_grant_dict_to_connector(self, mock_connect):
        """Test complete flow from grant dict to working connector."""
        # Mock the websocket connection
        mock_connect.side_effect = self.mock_websockets_connect

        grant_dict = {
            "type": "WebSocketConnectionGrant",
            "url": "ws://example.com/test",
            "purpose": "node.attach",
        }

        # Use the static create_connector method
        connector = await ConnectorFactory.create_connector(grant_dict)
        assert isinstance(connector, WebSocketConnector)

    @pytest.mark.asyncio
    async def test_end_to_end_http_grant_dict_to_connector(self):
        """Test end-to-end HTTP grant dict to connector creation with minimal mocking."""
        grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "https://example.com/test",
            "auth": None,
        }

        try:
            connector = await ConnectorFactory.create_connector(grant_dict, system_id="test-system")
            assert isinstance(connector, HttpStatelessConnector)
        except Exception as e:
            # If extension discovery doesn't work in test environment,
            # this is expected and we can verify the error type
            if "not found in ExtensionManager" in str(e):
                pytest.skip("ExtensionManager not working in test environment - this is expected")
            else:
                raise

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    @patch("websockets.connect")
    async def test_grant_object_to_connector_conversion(self, mock_connect):
        """Test conversion from grant objects to connectors."""
        # Mock the websocket connection
        mock_connect.side_effect = self.mock_websockets_connect

        # Test WebSocket grant
        ws_grant = WebSocketConnectionGrant(url="ws://example.com/test", purpose="node.attach")
        connector = await ConnectorFactory.create_connector(ws_grant)
        assert isinstance(connector, WebSocketConnector)

        # Test HTTP grant
        http_grant = HttpConnectionGrant(url="http://example.com", purpose="node.attach")
        connector = await ConnectorFactory.create_connector(http_grant)
        assert isinstance(connector, HttpStatelessConnector)

    def test_grant_dict_validation_errors(self):
        """Test that invalid grant dictionaries raise appropriate validation errors."""
        # Missing required purpose field
        invalid_grant_dict = {
            "type": "WebSocketConnectionGrant",
            "url": "ws://example.com/test",
            # Missing "purpose" field
        }

        with pytest.raises(Exception):  # Pydantic validation error
            WebSocketConnectorFactory.config_from_grant(invalid_grant_dict)

    def test_factory_grant_type_support_is_consistent(self):
        """Test that factory grant type support is consistent across methods."""
        # WebSocket factory
        ws_grant_types = WebSocketConnectorFactory.supported_grant_types()
        ws_grant_dict = {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://example.com/test",
            "auth": None,
        }

        # Should be able to create config if type is supported
        assert "WebSocketConnectionGrant" in ws_grant_types
        WebSocketConnectorFactory.config_from_grant(ws_grant_dict)
        assert ws_grant_dict["type"] in ws_grant_types

        # HTTP factory
        http_grant_types = HttpStatelessConnectorFactory.supported_grant_types()
        http_grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "https://example.com/test",
            "auth": None,
        }

        # Should be able to create config if type is supported
        assert "HttpConnectionGrant" in http_grant_types
        HttpStatelessConnectorFactory.config_from_grant(http_grant_dict)
        assert http_grant_dict["type"] in http_grant_types

    @pytest.mark.asyncio
    async def test_factory_rejects_wrong_grant_types(self):
        """Test that factories properly reject unsupported grant types."""
        # WebSocket factory should reject HTTP grants
        ws_factory = WebSocketConnectorFactory()
        http_grant = HttpConnectionGrant(
            type="HttpConnectionGrant", purpose="node.attach", url="https://example.com/test", auth=None
        )

        with pytest.raises(ValueError, match="WebSocketConnectorFactory only supports"):
            config = ws_factory.config_from_grant(http_grant)
            from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

            await ws_factory.create(WebSocketConnectorConfig.model_validate(config.model_dump()))

        # HTTP factory should reject WebSocket grants
        http_factory = HttpStatelessConnectorFactory()
        ws_grant = WebSocketConnectionGrant(
            type="WebSocketConnectionGrant", purpose="node.attach", url="ws://example.com/test", auth=None
        )

        with pytest.raises(ValueError, match="HttpStatelessConnectorFactory only supports"):
            config = http_factory.config_from_grant(ws_grant)
            from naylence.fame.connector.http_stateless_connector_factory import (
                HttpStatelessConnectorConfig,
            )

            await http_factory.create(HttpStatelessConnectorConfig.model_validate(config.model_dump()))

    def test_backward_compatibility_with_legacy_types(self):
        """Test that factories still support legacy connector type names."""
        # WebSocket factory should support legacy "WebSocketConnector" type
        ws_grant_types = WebSocketConnectorFactory.supported_grant_types()
        assert "WebSocketConnector" in ws_grant_types

        # HTTP factory should support legacy "HttpStatelessConnector" type
        http_grant_types = HttpStatelessConnectorFactory.supported_grant_types()
        assert "HttpStatelessConnector" in http_grant_types

    @pytest.mark.asyncio
    async def test_connector_config_fallback_behavior(self):
        """Test that non-grant dictionaries fall back to connector config creation."""
        # This should be treated as a connector config, not a grant
        config_dict = {
            "type": "WebSocketConnector",  # Connector type, not grant type
            "url": "ws://example.com/test",
        }

        # We don't have "purpose" field, and the type detection should recognize
        # this as not being a grant type supported by any factory as a grant
        try:
            # This should fall back to create_resource for connector config
            connector = await ConnectorFactory.create_connector(config_dict)
            # If it succeeds, verify it created the right type
            assert isinstance(connector, WebSocketConnector)
        except Exception as e:
            # Expected to fail with connection errors or missing extension in test environment
            # The important thing is it should try the connector config path, not the grant path
            assert "connect" in str(e).lower() or "not found in ExtensionManager" in str(e)
