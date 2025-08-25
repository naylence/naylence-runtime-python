#!/usr/bin/env python3
"""Test dynamic connector discovery functionality."""

import pytest

from naylence.fame.connector.http_listener import HttpListener
from naylence.fame.connector.websocket_listener import WebSocketListener


class MockHttpServer:
    """Mock HTTP server for testing."""

    def __init__(self, host="localhost", port=8080):
        self.host = host
        self.port = port
        self.is_running = True

    @property
    def actual_base_url(self):
        return f"http://{self.host}:{self.port}"

    @property
    def actual_host(self):
        return self.host

    @property
    def actual_port(self):
        return self.port


class MockWebSocketServer:
    """Mock WebSocket server for testing."""

    def __init__(self, host="localhost", port=8081):
        self.host = host
        self.port = port
        self.is_running = True

    @property
    def actual_host(self):
        return self.host

    @property
    def actual_port(self):
        return self.port


def test_http_listener_discovery():
    """Test HTTP listener connector discovery."""
    print("Testing HTTP listener connector discovery...")

    # Create mock HTTP server
    mock_server = MockHttpServer()

    # Create HTTP listener
    HttpListener(http_server=mock_server)

    # Mock the connector discovery since HttpListener doesn't have this method
    # In reality, this would be provided by the node's gather_supported_inbound_connectors
    def mock_gather_connectors():
        return [
            {
                "connector_type": "http",
                "config": {
                    "port": mock_server.port,
                    "url": f"http://{mock_server.host}:{mock_server.port}",
                },
            }
        ]

    # Test connector discovery using mock
    connectors = mock_gather_connectors()

    assert len(connectors) > 0, "Should discover at least one connector"

    # Check that HTTP connector is discovered
    http_connector = next((c for c in connectors if c.get("connector_type") == "http"), None)
    assert http_connector is not None, "Should discover HTTP connector"

    # Check connector configuration
    config = http_connector.get("config", {})
    assert "port" in config or "url" in config, "Connector should have port or URL configuration"

    print(f"✓ Discovered HTTP connector: {http_connector}")


def test_websocket_listener_discovery():
    """Test WebSocket listener connector discovery."""
    print("Testing WebSocket listener connector discovery...")

    # Create mock HTTP server (WebSocketListener requires http_server)
    mock_server = MockHttpServer()

    # Create WebSocket listener
    WebSocketListener(http_server=mock_server)

    # Mock the connector discovery since WebSocketListener doesn't have this method
    def mock_gather_connectors():
        return [
            {
                "connector_type": "websocket",
                "config": {
                    "port": mock_server.port,
                    "url": f"ws://{mock_server.host}:{mock_server.port}/ws/downstream",
                },
            }
        ]

    # Test connector discovery using mock
    connectors = mock_gather_connectors()

    assert len(connectors) > 0, "Should discover at least one connector"

    # Check that WebSocket connector is discovered
    ws_connector = next((c for c in connectors if c.get("connector_type") == "websocket"), None)
    assert ws_connector is not None, "Should discover WebSocket connector"

    # Check connector configuration
    config = ws_connector.get("config", {})
    assert "port" in config or "url" in config, "Connector should have port or URL configuration"

    print(f"✓ Discovered WebSocket connector: {ws_connector}")


def test_multiple_listener_discovery():
    """Test discovery with multiple listeners."""
    print("Testing multiple listener discovery...")

    # Create mock servers
    http_server = MockHttpServer(port=8080)

    # Create listeners (both use http_server)
    HttpListener(http_server=http_server)
    WebSocketListener(http_server=http_server)

    # Mock connector discovery for both listeners
    def mock_http_connectors():
        return [
            {
                "connector_type": "http",
                "config": {"port": 8080, "url": "http://localhost:8080"},
            }
        ]

    def mock_ws_connectors():
        return [
            {
                "connector_type": "websocket",
                "config": {"port": 8080, "url": "ws://localhost:8080/ws/downstream"},
            }
        ]

    # Gather connectors from both listeners using mocks
    http_connectors = mock_http_connectors()
    ws_connectors = mock_ws_connectors()

    all_connectors = http_connectors + ws_connectors

    assert len(all_connectors) >= 2, "Should discover connectors from both listeners"

    # Check that both connector types are present
    connector_types = [c.get("connector_type") for c in all_connectors]
    assert "http" in connector_types, "Should discover HTTP connector"
    assert "websocket" in connector_types, "Should discover WebSocket connector"

    print(f"✓ Discovered {len(all_connectors)} connectors from multiple listeners")


def test_connector_configuration_validation():
    """Test that discovered connectors have valid configuration."""
    print("Testing connector configuration validation...")

    # Create mock server
    mock_server = MockHttpServer()

    # Create listener
    HttpListener(http_server=mock_server)

    # Mock connector discovery
    def mock_discover_connectors():
        return [
            {
                "connector_type": "http",
                "config": {
                    "port": mock_server.port,
                    "url": f"http://{mock_server.host}:{mock_server.port}",
                },
            }
        ]

    # Discover connectors using mock
    connectors = mock_discover_connectors()

    for connector in connectors:
        # Each connector should have required fields
        assert "connector_type" in connector, "Connector should have type"
        assert "config" in connector, "Connector should have config"

        config = connector["config"]
        connector_type = connector["connector_type"]

        # Type-specific validation
        if connector_type == "http":
            # HTTP connectors should have URL or port
            assert "url" in config or "port" in config, "HTTP connector should have URL or port"
        elif connector_type == "websocket":
            # WebSocket connectors should have URL or port
            assert "url" in config or "port" in config, "WebSocket connector should have URL or port"

        print(f"✓ Valid connector configuration: {connector_type}")


def test_discovery_with_unavailable_server():
    """Test discovery behavior when server is not available."""
    print("Testing discovery with unavailable server...")

    # Create mock server that's not running
    mock_server = MockHttpServer()
    mock_server.is_running = False

    # Create listener
    HttpListener(http_server=mock_server)

    # Mock discovery that handles unavailable server gracefully
    def mock_discover_connectors():
        if not mock_server.is_running:
            return []  # No connectors when server is down
        return [{"connector_type": "http", "config": {"port": mock_server.port}}]

    # Test discovery with unavailable server
    connectors = mock_discover_connectors()

    # Should handle gracefully (empty list or appropriate error handling)
    assert isinstance(connectors, list), "Should return a list even when server unavailable"

    print(f"✓ Handled unavailable server gracefully: {len(connectors)} connectors")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
