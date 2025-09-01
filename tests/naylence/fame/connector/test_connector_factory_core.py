"""Core tests for ConnectorFactory dynamic mapping functionality."""

from unittest.mock import Mock, patch

import pytest

from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorFactory
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorFactory
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant


class TestConnectorFactoryCore:
    """Core tests for ConnectorFactory dynamic mapping functionality."""

    def test_websocket_factory_supported_grant_types_class_method(self):
        """Test WebSocketConnectorFactory.supported_grant_types() works as class method."""
        # Should work without instantiating the factory
        grant_types = WebSocketConnectorFactory.supported_grant_types()

        assert isinstance(grant_types, list)
        assert "WebSocketConnectionGrant" in grant_types
        assert "WebSocketConnector" in grant_types  # Legacy support

    def test_http_factory_supported_grant_types_class_method(self):
        """Test HttpStatelessConnectorFactory.supported_grant_types() works as class method."""
        # Should work without instantiating the factory
        grant_types = HttpStatelessConnectorFactory.supported_grant_types()

        assert isinstance(grant_types, list)
        assert "HttpConnectionGrant" in grant_types
        assert "HttpStatelessConnector" in grant_types  # Legacy support

    def test_websocket_factory_config_from_grant_class_method(self):
        """Test WebSocketConnectorFactory.config_from_grant() works with dict as class method."""
        grant_dict = {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "wss://example.com/test",
            "auth": None,
        }

        # Should work without instantiating the factory
        config = WebSocketConnectorFactory.config_from_grant(grant_dict)

        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        assert isinstance(config, WebSocketConnectorConfig)
        assert config.type == "WebSocketConnector"
        assert config.url == "wss://example.com/test"
        assert config.url == "wss://example.com/test"

    def test_http_factory_config_from_grant_class_method(self):
        """Test HttpStatelessConnectorFactory.config_from_grant() works with dict as class method."""
        grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "https://example.com/test",
            "auth": None,
        }

        # Should work without instantiating the factory
        config = HttpStatelessConnectorFactory.config_from_grant(grant_dict)

        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        assert isinstance(config, HttpStatelessConnectorConfig)
        assert config.type == "HttpStatelessConnector"
        assert config.url == "https://example.com/test"

    @pytest.mark.asyncio
    async def test_websocket_factory_create_connector_using_config_from_grant(self):
        """Test WebSocketConnectorFactory by converting grant to config and creating connector."""
        factory = WebSocketConnectorFactory()
        grant = WebSocketConnectionGrant(
            type="WebSocketConnectionGrant",
            purpose="node.attach",
            url="ws://example.com/test",  # Use ws:// to avoid SSL issues
            auth=None,
        )

        # Convert grant to config
        config = factory.config_from_grant(grant)
        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        typed_config = WebSocketConnectorConfig.model_validate(config.model_dump())

        # Mock the websocket connection to avoid actual network calls
        with patch.object(factory, "_client_factory") as mock_client_factory:
            mock_websocket = Mock()
            mock_client_factory.return_value = mock_websocket

            connector = await factory.create(typed_config, system_id="test-system")

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
        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        typed_config = HttpStatelessConnectorConfig.model_validate(config.model_dump())

        connector = await factory.create(typed_config)

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

    @pytest.mark.asyncio
    async def test_http_factory_rejects_wrong_grant_type(self):
        """Test HttpStatelessConnectorFactory rejects unsupported grant types."""
        factory = HttpStatelessConnectorFactory()
        grant = WebSocketConnectionGrant(  # Wrong grant type for HTTP factory
            type="WebSocketConnectionGrant", purpose="node.attach", url="wss://example.com/test", auth=None
        )

        with pytest.raises(
            ValueError, match="HttpStatelessConnectorFactory only supports HttpConnectionGrant"
        ):
            config = factory.config_from_grant(grant)
            from naylence.fame.connector.http_stateless_connector_factory import (
                HttpStatelessConnectorConfig,
            )

            await factory.create(HttpStatelessConnectorConfig.model_validate(config.model_dump()))

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

    def test_factory_grant_type_support_consistency(self):
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

    def test_legacy_grant_type_support(self):
        """Test that factories still support legacy connector type names."""
        # WebSocket factory should support legacy "WebSocketConnector" type
        ws_grant_types = WebSocketConnectorFactory.supported_grant_types()
        assert "WebSocketConnector" in ws_grant_types

        # HTTP factory should support legacy "HttpStatelessConnector" type
        http_grant_types = HttpStatelessConnectorFactory.supported_grant_types()
        assert "HttpStatelessConnector" in http_grant_types

    def test_missing_type_field_validation(self):
        """Test that missing type field raises appropriate error."""
        config_dict = {
            "url": "ws://example.com/test"
            # Missing "type" field
        }

        with pytest.raises(ValueError, match="Missing 'type' field in configuration"):
            import asyncio

            asyncio.run(ConnectorFactory.create_connector(config_dict))

    def test_invalid_input_type_validation(self):
        """Test that invalid input types raise appropriate error."""
        invalid_input = "not_a_dict_or_grant_or_config"

        with pytest.raises(ValueError, match="Missing 'type' field in configuration"):
            import asyncio

            asyncio.run(ConnectorFactory.create_connector(invalid_input))  # type: ignore

    @pytest.mark.asyncio
    async def test_abstract_methods_are_implemented(self):
        """Test that all abstract methods are properly implemented."""
        # Test that concrete factories implement all abstract methods
        factories = [WebSocketConnectorFactory, HttpStatelessConnectorFactory]

        for factory_class in factories:
            # Should be able to call class methods
            grant_types = factory_class.supported_grant_types()
            assert isinstance(grant_types, list)
            assert len(grant_types) > 0

            # Should be able to create config from dict
            grant_dict = {
                "type": grant_types[0],  # Use the first supported grant type
                "purpose": "node.attach",
                "url": "http://example.com" if "Http" in grant_types[0] else "ws://example.com",
                "auth": None,
            }

            # This should not raise NotImplementedError
            factory_class.config_from_grant(grant_dict)
            assert grant_dict["type"] == grant_types[0]

    @pytest.mark.asyncio
    async def test_dynamic_factory_discovery_concept(self):
        """Test the concept of dynamic factory discovery (without ExtensionManager)."""
        # Test the logic that would be used in the real dynamic discovery
        grant_type = "WebSocketConnectionGrant"

        # Manually test what the dynamic discovery would do
        factories_to_test = [WebSocketConnectorFactory, HttpStatelessConnectorFactory]
        matching_factory = None

        for factory_class in factories_to_test:
            if grant_type in factory_class.supported_grant_types():
                matching_factory = factory_class
                break

        assert matching_factory is not None
        assert matching_factory == WebSocketConnectorFactory

        # Test with HTTP grant type
        grant_type = "HttpConnectionGrant"
        matching_factory = None

        for factory_class in factories_to_test:
            if grant_type in factory_class.supported_grant_types():
                matching_factory = factory_class
                break

        assert matching_factory is not None
        assert matching_factory == HttpStatelessConnectorFactory

    @pytest.mark.asyncio
    async def test_grant_to_connector_roundtrip(self):
        """Test complete grant creation and connector creation roundtrip."""
        # WebSocket roundtrip
        ws_grant_dict = {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://example.com/test",
            "auth": None,
        }

        # Create config from dict
        ws_config = WebSocketConnectorFactory.config_from_grant(ws_grant_dict)
        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        assert isinstance(ws_config, WebSocketConnectorConfig)

        # Create connector from config
        ws_factory = WebSocketConnectorFactory()
        with patch.object(ws_factory, "_client_factory") as mock_client:
            mock_client.return_value = Mock()
            ws_connector = await ws_factory.create(
                WebSocketConnectorConfig.model_validate(ws_config.model_dump())
            )
            assert isinstance(ws_connector, WebSocketConnector)

        # HTTP roundtrip
        http_grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "https://example.com/test",
            "auth": None,
        }

        # Create config from dict
        http_config = HttpStatelessConnectorFactory.config_from_grant(http_grant_dict)
        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig

        assert isinstance(http_config, HttpStatelessConnectorConfig)

        # Create connector from config
        http_factory = HttpStatelessConnectorFactory()
        http_connector = await http_factory.create(
            HttpStatelessConnectorConfig.model_validate(http_config.model_dump())
        )
        assert isinstance(http_connector, HttpStatelessConnector)
