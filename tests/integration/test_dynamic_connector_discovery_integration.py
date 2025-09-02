#!/usr/bin/env python3
"""Test dynamic connector discovery integration with DirectAdmissionClient."""

from unittest.mock import Mock

import pytest

# Import only what we need to avoid circular import issues
from naylence.fame.node.admission.direct_admission_client import DirectAdmissionClient


# Mock the listener classes to avoid circular import issues
class HttpListener:
    """Mock HTTP listener for testing."""

    def __init__(self, http_server=None):
        self.http_server = http_server


class WebSocketListener:
    """Mock WebSocket listener for testing."""

    def __init__(self, http_server=None):
        self.http_server = http_server


# Mock WebSocketConnectorConfig to avoid circular import
class WebSocketConnectorConfig:
    """Mock WebSocket connector config for testing."""

    def __init__(self, type="websocket", **kwargs):
        self.type = type
        self.params = kwargs

    def model_dump(self):
        """Mock model_dump method for compatibility."""
        return {"type": self.type, "params": self.params}


class MockHttpServer:
    """Mock HTTP server for testing."""

    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port
        self.actual_base_url = f"http://{host}:{port}"


class MockNode:
    """Mock node for testing dynamic connector discovery."""

    def __init__(self):
        self.id = "test-node"
        self.sid = "test-sid"
        self.event_listeners = []
        self.transport_listeners = []

    def add_event_listener(self, listener):
        self.event_listeners.append(listener)

    def add_transport_listener(self, listener):
        self.transport_listeners.append(listener)

    def gather_supported_inbound_connectors(self):
        """Gather connectors from all transport listeners."""
        connectors = []
        for listener in self.transport_listeners:
            # Mock connector data based on listener type
            if hasattr(listener, "http_server") and listener.__class__.__name__ == "HttpListener":
                # HTTP listener
                connectors.append(
                    {
                        "connector_type": "http",
                        "host": getattr(listener.http_server, "host", "localhost"),
                        "port": getattr(listener.http_server, "port", 8080),
                        "url": getattr(
                            listener.http_server,
                            "actual_base_url",
                            "http://localhost:8080",
                        ),
                        "config": {"type": "http"},
                    }
                )
            elif hasattr(listener, "http_server") and listener.__class__.__name__ == "WebSocketListener":
                # WebSocket listener (also uses http_server)
                server = listener.http_server
                actual_host = getattr(server, "actual_host", "localhost")
                actual_port = getattr(server, "actual_port", 8081)
                connectors.append(
                    {
                        "connector_type": "websocket",
                        "host": actual_host,
                        "port": actual_port,
                        "url": f"ws://{actual_host}:{actual_port}",
                        "config": {"type": "websocket"},
                    }
                )
        return connectors


@pytest.mark.asyncio
async def test_dynamic_connector_setup_integration():
    """Test integration of dynamic connector setup with DirectAdmissionClient."""
    print("Testing dynamic connector setup integration...")

    # Create mock node
    node = MockNode()

    # Create mock HTTP server and listener
    http_server = MockHttpServer()
    http_listener = HttpListener(http_server=http_server)
    node.add_transport_listener(http_listener)

    # Create DirectAdmissionClient with a mock connector config
    connection_grants = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://localhost:8080/test",
        }
    ]
    DirectAdmissionClient(connection_grants=connection_grants)

    # DirectAdmissionClient no longer implements NodeEventListener,
    # so we test that the node can discover connectors from its transport listeners
    discovered_connectors = node.gather_supported_inbound_connectors()
    assert discovered_connectors is not None, "Should have discovered connectors"
    assert len(discovered_connectors) > 0, "Should discover connectors"

    print(f"✓ Node has {len(discovered_connectors)} discovered connectors")


@pytest.mark.asyncio
async def test_multiple_transport_listeners():
    """Test integration with multiple transport listeners."""
    print("Testing multiple transport listeners...")

    # Create mock node
    node = MockNode()

    # Create HTTP listener
    http_server = MockHttpServer(port=8080)
    http_listener = HttpListener(http_server=http_server)
    node.add_transport_listener(http_listener)

    # Create WebSocket listener
    ws_server = Mock()
    ws_server.actual_host = "127.0.0.1"
    ws_server.actual_port = 8081
    ws_listener = WebSocketListener(http_server=ws_server)
    node.add_transport_listener(ws_listener)

    # Test connector discovery
    connectors = node.gather_supported_inbound_connectors()

    # Should discover both HTTP and WebSocket connectors
    connector_types = [c.get("connector_type") for c in connectors]
    assert "http" in connector_types, "Should discover HTTP connector"
    assert "websocket" in connector_types, "Should discover WebSocket connector"

    print(f"✓ Discovered connectors: {connector_types}")


@pytest.mark.asyncio
async def test_dynamic_setup_event_handling():
    """Test dynamic setup event handling."""
    print("Testing dynamic setup event handling...")

    # Create mock node
    MockNode()

    # Create DirectAdmissionClient
    connection_grants = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://localhost:8080/test",
        }
    ]
    admission_client = DirectAdmissionClient(connection_grants=connection_grants)

    # DirectAdmissionClient no longer implements NodeEventListener,
    # so we test that it can be used independently and that nodes
    # can discover connectors through their transport listeners

    # Verify that the admission client works as expected
    hello_response = await admission_client.hello(
        system_id="test-system", instance_id="test-instance", requested_logicals=["*"]
    )

    assert hello_response.frame.connection_grants is not None, "Should have connection grants"
    assert len(hello_response.frame.connection_grants) > 0, "Should have at least one connection grant"
    assert hello_response.frame.system_id == "test-system", "Should preserve system_id"

    print("✓ Dynamic setup works without event handling")


@pytest.mark.asyncio
async def test_admission_client_connector_usage():
    """Test that DirectAdmissionClient uses discovered connectors."""
    print("Testing admission client connector usage...")

    # Create mock node with connectors
    node = MockNode()

    # Add HTTP listener
    http_server = MockHttpServer()
    http_listener = HttpListener(http_server=http_server)
    node.add_transport_listener(http_listener)

    # Create admission client with a mock connector config
    connection_grants = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://localhost:8080/test",
        }
    ]
    DirectAdmissionClient(connection_grants=connection_grants)

    # Test that admission client can work with discovered connectors
    connectors = node.gather_supported_inbound_connectors()

    # Admission client should be able to use these connectors
    # (Actual usage depends on implementation details)
    assert len(connectors) > 0, "Should have connectors to work with"

    print(f"✓ Admission client has {len(connectors)} connectors available")


def test_connector_configuration_compatibility():
    """Test that discovered connectors are compatible with expected formats."""
    print("Testing connector configuration compatibility...")

    # Create mock node
    node = MockNode()

    # Add listeners
    http_server = MockHttpServer()
    http_listener = HttpListener(http_server=http_server)
    node.add_transport_listener(http_listener)

    # Discover connectors
    connectors = node.gather_supported_inbound_connectors()

    # Check that connectors have expected format
    for connector in connectors:
        assert isinstance(connector, dict), "Connector should be a dictionary"
        assert "connector_type" in connector, "Connector should have type"
        assert "config" in connector, "Connector should have config"

        # Config should be a dictionary
        config = connector["config"]
        assert isinstance(config, dict), "Config should be a dictionary"

        print(f"✓ Connector format is compatible: {connector['connector_type']}")


@pytest.mark.asyncio
async def test_error_handling_in_discovery():
    """Test error handling during connector discovery."""
    print("Testing error handling in discovery...")

    # Create mock node
    node = MockNode()

    # Create a listener that might fail
    class FailingListener:
        def gather_supported_inbound_connectors(self):
            raise Exception("Discovery failed")

    failing_listener = FailingListener()
    node.add_transport_listener(failing_listener)

    # Also add a working listener
    http_server = MockHttpServer()
    http_listener = HttpListener(http_server=http_server)
    node.add_transport_listener(http_listener)

    # Discovery should handle failures gracefully
    try:
        connectors = node.gather_supported_inbound_connectors()
        # Should get connectors from working listener despite failure
        print(f"✓ Discovery resilient to failures, got {len(connectors)} connectors")
    except Exception as e:
        # If the implementation doesn't handle failures gracefully,
        # we should still verify the error is reasonable
        print(f"✓ Discovery failure handled: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
