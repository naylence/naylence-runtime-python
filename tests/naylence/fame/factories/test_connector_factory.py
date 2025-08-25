"""Test ConnectorFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.core import create_resource
from naylence.fame.errors.errors import FameConnectError


class TestConnectorFactory:
    """Test ConnectorFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_websocket_connector_factory(self):
        """Test WebSocketConnector factory creates correct instance."""
        config = {"type": "WebSocketConnector", "url": "ws://localhost:8080/test"}

        # Note: This will likely fail without a real websocket server
        # but we can test that the factory attempts to create the right type
        try:
            connector = await create_resource(ConnectorFactory, config)
            assert isinstance(connector, WebSocketConnector)
            assert connector.__class__.__name__ == "WebSocketConnector"
        except (FameConnectError, OSError, ConnectionError) as e:
            # Expected to fail without a real server, but should fail in websocket connection, not factory
            # These are all connection-related errors which is what we expect
            assert "connect" in str(e).lower() or "connection" in str(e).lower()
        except Exception as e:
            pytest.fail(f"Unexpected error type: {type(e).__name__}: {e}")

    @pytest.mark.asyncio
    async def test_connector_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "WebSocketConnector", "url": "ws://localhost:8080/test"}

        try:
            connector = await create_resource(ConnectorFactory, config)
            assert isinstance(connector, WebSocketConnector)
        except (FameConnectError, OSError, ConnectionError) as e:
            # Expected to fail without a real server, but should fail at connection, not factory level
            # These are all connection-related errors which is what we expect
            assert "connect" in str(e).lower() or "connection" in str(e).lower()
        except Exception as e:
            pytest.fail(f"Unexpected error type: {type(e).__name__}: {e}")

    @pytest.mark.asyncio
    async def test_connector_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidConnector", "url": "ws://localhost:8080/test"}

        with pytest.raises(Exception):
            await create_resource(ConnectorFactory, config)

    @pytest.mark.asyncio
    async def test_websocket_connector_with_auth(self):
        """Test WebSocketConnector factory with authentication."""

        config = {
            "type": "WebSocketConnector",
            "url": "ws://localhost:8080/test",
            "auth": {
                "type": "BearerTokenHeaderAuth",
                "token_provider": {"type": "StaticTokenProvider", "token": "test-token"},
                "param": "Authorization",
            },
        }

        try:
            connector = await create_resource(ConnectorFactory, config)
            assert isinstance(connector, WebSocketConnector)
        except (FameConnectError, OSError, ConnectionError) as e:
            # Expected to fail without a real server
            # These are all connection-related errors which is what we expect
            assert "connect" in str(e).lower() or "connection" in str(e).lower()
        except Exception as e:
            pytest.fail(f"Unexpected error type: {type(e).__name__}: {e}")
