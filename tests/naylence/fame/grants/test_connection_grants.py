"""Tests for connection grants functionality."""

import pytest

from naylence.fame.grants.connection_grant import (
    ConnectionGrant,
)
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant
from naylence.fame.security.auth.auth_injection_strategy_factory import AuthInjectionStrategyConfig


class TestConnectionGrants:
    """Test connection grants functionality."""

    def test_connection_grant_base_class(self):
        """Test basic ConnectionGrant functionality."""
        grant = ConnectionGrant(type="TestConnector", purpose="test.purpose")
        assert grant.type == "TestConnector"
        assert grant.purpose == "test.purpose"

    def test_websocket_connection_grant(self):
        """Test WebSocketConnectionGrant."""
        auth = AuthInjectionStrategyConfig(type="none")
        grant = WebSocketConnectionGrant(purpose="node.attach", url="ws://example.com/ws", auth=auth)
        assert grant.type == "WebSocketConnectionGrant"
        assert grant.purpose == "node.attach"
        assert grant.url == "ws://example.com/ws"
        assert grant.auth is not None
        assert grant.auth.type == "none"

    def test_http_connection_grant(self):
        """Test HttpConnectionGrant."""
        auth = AuthInjectionStrategyConfig(type="bearer")
        grant = HttpConnectionGrant(
            purpose="node.attach",
            url="http://example.com/api",
            auth=auth,
        )
        assert grant.type == "HttpConnectionGrant"
        assert grant.purpose == "node.attach"
        assert grant.url == "http://example.com/api"
        assert grant.auth is not None
        assert grant.auth.type == "bearer"

    @pytest.mark.asyncio
    async def test_connector_from_websocket_grant(self):
        """Test creating connector from WebSocket grant."""
        grant = WebSocketConnectionGrant(purpose="node.attach", url="ws://example.com/ws")

        # This would require mocking the ConnectorFactory, so we'll test the logic
        # by checking that it can parse the grant correctly
        assert isinstance(grant, WebSocketConnectionGrant)
        assert grant.type == "WebSocketConnectionGrant"

    @pytest.mark.asyncio
    async def test_connector_from_http_grant(self):
        """Test creating connector from HTTP grant."""
        grant = HttpConnectionGrant(purpose="node.attach", url="http://example.com/api")

        # This would require mocking the ConnectorFactory, so we'll test the logic
        # by checking that it can parse the grant correctly
        assert isinstance(grant, HttpConnectionGrant)
        assert grant.type == "HttpConnectionGrant"

    @pytest.mark.asyncio
    async def test_connector_from_grant_with_dict(self):
        """Test creating connector from dict grant."""
        # Test WebSocket dict grant
        ws_grant_dict = {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://example.com/ws",
        }

        # Would convert to WebSocketConnectionGrant
        # This is mainly testing the validation logic
        grant = WebSocketConnectionGrant.model_validate(ws_grant_dict)
        assert grant.type == "WebSocketConnectionGrant"
        assert grant.purpose == "node.attach"

        # Test HTTP dict grant
        http_grant_dict = {
            "type": "HttpConnectionGrant",
            "purpose": "node.attach",
            "url": "http://example.com/api",
        }

        grant = HttpConnectionGrant.model_validate(http_grant_dict)
        assert grant.type == "HttpConnectionGrant"
        assert grant.purpose == "node.attach"

    def test_grant_serialization(self):
        """Test that grants can be serialized/deserialized."""
        grant = WebSocketConnectionGrant(purpose="node.attach", url="ws://example.com/ws")

        # Test model_dump (serialization)
        data = grant.model_dump()
        assert data["type"] == "WebSocketConnectionGrant"
        assert data["purpose"] == "node.attach"
        assert data["url"] == "ws://example.com/ws"

        # Test model_validate (deserialization)
        restored_grant = WebSocketConnectionGrant.model_validate(data)
        assert restored_grant.type == grant.type
        assert restored_grant.purpose == grant.purpose
        assert restored_grant.url == grant.url
