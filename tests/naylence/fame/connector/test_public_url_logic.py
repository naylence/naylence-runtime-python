"""
Test public_url functionality using mock objects.

This test validates the core logic without importing the full framework.
For full integration testing, see integration tests which test the actual node architecture.
"""

import pytest


class MockHttpServer:
    """Mock HTTP server for testing."""

    def actual_base_url(self):
        return "http://127.0.0.1:8080"


class MockHttpListener:
    """Mock HTTP listener for testing public URL logic."""

    def __init__(self, public_url=None):
        self._public_url = public_url
        self._http_server = MockHttpServer()

    @property
    def base_url(self):
        """Use public URL from node config if available, otherwise fall back to actual server URL."""
        return self._public_url or self._http_server.actual_base_url()

    @property
    def upstream_endpoint(self):
        return "/fame/v1/ingress/upstream"

    def as_inbound_connector(self):
        """Return connector configuration for reverse connections."""
        if not self.base_url:
            return None

        return {
            "type": "HttpStatelessConnector",
            "url": f"{self.base_url}{self.upstream_endpoint}",
        }


class MockWebSocketListener:
    """Mock WebSocket listener for testing public URL logic."""

    def __init__(self, public_url=None):
        self._public_url = public_url
        self._http_server = MockHttpServer()

    @property
    def base_url(self):
        """Use public URL from node config if available, otherwise fall back to actual server URL."""
        return self._public_url or self._http_server.actual_base_url()

    @property
    def upstream_endpoint(self):
        return "/fame/v1/ingress/upstream/ws"

    def as_inbound_connector(self):
        """Return connector configuration for reverse connections."""
        if not self.base_url:
            return None

        return {
            "type": "WebSocketStatelessConnector",
            "url": f"{self.base_url.replace('http://', 'ws://').replace('https://', 'wss://')}{self.upstream_endpoint}",
        }


def test_http_listener_without_public_url():
    """Test HTTP listener falls back to actual server URL when no public URL is configured."""
    listener = MockHttpListener()
    assert listener.base_url == "http://127.0.0.1:8080", "Should use actual server URL"


def test_http_listener_with_public_url():
    """Test HTTP listener uses public URL when configured."""
    listener = MockHttpListener(public_url="https://api.example.com")
    assert listener.base_url == "https://api.example.com", "Should use configured public URL"


def test_http_listener_connector_config():
    """Test HTTP listener generates correct connector configuration."""
    listener = MockHttpListener(public_url="https://api.example.com")
    connector = listener.as_inbound_connector()

    expected = {
        "type": "HttpStatelessConnector",
        "url": "https://api.example.com/fame/v1/ingress/upstream",
    }
    assert connector == expected, "Should generate correct HTTP connector config"


def test_websocket_listener_without_public_url():
    """Test WebSocket listener falls back to actual server URL when no public URL is configured."""
    listener = MockWebSocketListener()
    assert listener.base_url == "http://127.0.0.1:8080", "Should use actual server URL"


def test_websocket_listener_with_public_url():
    """Test WebSocket listener uses public URL when configured."""
    listener = MockWebSocketListener(public_url="https://api.example.com")
    assert listener.base_url == "https://api.example.com", "Should use configured public URL"


def test_websocket_listener_connector_config():
    """Test WebSocket listener generates correct connector configuration with protocol conversion."""
    listener = MockWebSocketListener(public_url="https://api.example.com")
    connector = listener.as_inbound_connector()

    expected = {
        "type": "WebSocketStatelessConnector",
        "url": "wss://api.example.com/fame/v1/ingress/upstream/ws",
    }
    assert connector == expected, "Should generate correct WebSocket connector config with wss://"


def test_websocket_http_to_ws_conversion():
    """Test WebSocket listener converts http:// to ws:// protocol."""
    listener = MockWebSocketListener(public_url="http://api.example.com")
    connector = listener.as_inbound_connector()

    expected = {
        "type": "WebSocketStatelessConnector",
        "url": "ws://api.example.com/fame/v1/ingress/upstream/ws",
    }
    assert connector == expected, "Should convert http:// to ws://"


@pytest.mark.parametrize(
    "public_url,expected_http,expected_ws",
    [
        (None, "http://127.0.0.1:8080", "ws://127.0.0.1:8080"),
        ("http://localhost:8080", "http://localhost:8080", "ws://localhost:8080"),
        ("https://secure.example.com", "https://secure.example.com", "wss://secure.example.com"),
        ("http://api.test.local:9000", "http://api.test.local:9000", "ws://api.test.local:9000"),
    ],
)
def test_public_url_scenarios(public_url, expected_http, expected_ws):
    """Test various public URL scenarios for both HTTP and WebSocket listeners."""
    http_listener = MockHttpListener(public_url=public_url)
    ws_listener = MockWebSocketListener(public_url=public_url)

    assert http_listener.base_url == expected_http, f"HTTP listener should use {expected_http}"
    assert ws_listener.base_url == expected_http, f"WebSocket listener should use {expected_http} as base"

    # Check connector URLs
    http_connector = http_listener.as_inbound_connector()
    ws_connector = ws_listener.as_inbound_connector()

    expected_http_url = f"{expected_http}/fame/v1/ingress/upstream"
    expected_ws_url = f"{expected_ws}/fame/v1/ingress/upstream/ws"

    assert http_connector["url"] == expected_http_url, f"HTTP connector should use {expected_http_url}"
    assert ws_connector["url"] == expected_ws_url, f"WebSocket connector should use {expected_ws_url}"


def test_listener_without_base_url():
    """Test edge case where listener has no base URL."""

    class MockEmptyListener(MockHttpListener):
        @property
        def base_url(self):
            return None

    listener = MockEmptyListener()
    connector = listener.as_inbound_connector()
    assert connector is None, "Should return None when no base URL available"
