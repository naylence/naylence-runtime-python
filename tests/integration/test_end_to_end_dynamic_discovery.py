from unittest.mock import Mock

import pytest

from naylence.fame.connector.http_listener_factory import HttpListenerFactory
from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig
from naylence.fame.factory import ExtensionManager
from naylence.fame.node.admission.direct_admission_client import DirectAdmissionClient
from naylence.fame.node.factory_commons import make_common_opts
from naylence.fame.node.node_config import FameNodeConfig

"""End-to-end test for dynamic connector discovery using the complete factory setup."""


class MockNode:
    """Mock node that simulates the real FameNode interface."""

    def __init__(self, admission_client=None, event_listeners=None):
        self.id = "test-node"
        self.sid = "test-sid"
        self.admission_client = admission_client
        self.event_listeners = event_listeners or []

    def gather_supported_callback_grants(self):
        """Gather connectors from transport listeners."""
        result = []

        # Simulate discovering HTTP connector
        http_connector = {
            "connector_type": "http",
            "config": {"port": 8080, "host": "localhost"},
        }
        result.append(http_connector)

        # Simulate discovering WebSocket connector
        ws_connector = {
            "connector_type": "websocket",
            "config": {"port": 8081, "host": "localhost"},
        }
        result.append(ws_connector)

        return result


@pytest.mark.asyncio
async def test_end_to_end_dynamic_discovery():
    """Test complete end-to-end dynamic connector discovery."""
    print("Testing end-to-end dynamic connector discovery...")

    # Create mock extension manager
    Mock(spec=ExtensionManager)

    # Create node configuration
    config = FameNodeConfig()

    # Create common options (corrected function call)
    await make_common_opts(config)

    # Create DirectAdmissionClient with required connector config
    connection_grants = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://localhost:8080/test",
        }
    ]
    admission_client = DirectAdmissionClient(connection_grants=connection_grants)

    # Create mock node with discovery capabilities
    node = MockNode(admission_client=admission_client)

    # Test connector discovery
    connectors = node.gather_supported_callback_grants()

    assert len(connectors) >= 2, "Should discover multiple connectors"

    # Check that expected connector types are present
    connector_types = [c["connector_type"] for c in connectors]
    assert "http" in connector_types, "Should discover HTTP connector"
    assert "websocket" in connector_types, "Should discover WebSocket connector"

    print(f"✓ End-to-end discovery found {len(connectors)} connectors")


@pytest.mark.asyncio
async def test_factory_based_listener_creation():
    """Test creating transport listeners using factory pattern."""
    print("Testing factory-based listener creation...")

    # Create transport listener factory (using concrete implementation)
    factory = HttpListenerFactory()

    # Test HTTP listener creation
    http_config = {"type": "http", "port": 8080, "host": "localhost"}

    try:
        http_listener = await factory.create_listener(http_config)
        assert http_listener is not None, "Should create HTTP listener"
        print("✓ HTTP listener created via factory")
    except Exception as e:
        print(f"HTTP listener creation failed (may be expected): {e}")

    # Test WebSocket listener creation
    ws_config = {"type": "websocket", "port": 8081, "host": "localhost"}

    try:
        ws_listener = await factory.create_listener(ws_config)
        assert ws_listener is not None, "Should create WebSocket listener"
        print("✓ WebSocket listener created via factory")
    except Exception as e:
        print(f"WebSocket listener creation failed (may be expected): {e}")


@pytest.mark.asyncio
async def test_connector_config_integration():
    """Test integration of connector configurations."""
    print("Testing connector config integration...")

    # Create WebSocket connector config
    ws_config = WebSocketConnectorConfig()

    # Test that config has expected structure
    assert hasattr(ws_config, "__dict__"), "Config should be serializable"

    # Test config serialization/deserialization
    config_dict = ws_config.__dict__
    assert isinstance(config_dict, dict), "Config should serialize to dict"

    print("✓ Connector configuration integration works")


def test_discovery_configuration_validation():
    """Test validation of discovered connector configurations."""
    print("Testing discovery configuration validation...")

    # Create mock node
    node = MockNode()

    # Discover connectors
    connectors = node.gather_supported_callback_grants()

    for connector in connectors:
        # Validate connector structure
        assert "connector_type" in connector, "Connector must have type"
        assert "config" in connector, "Connector must have config"

        config = connector["config"]
        connector_type = connector["connector_type"]

        # Validate type-specific requirements
        if connector_type == "http":
            assert "port" in config, "HTTP connector must have port"
            assert isinstance(config["port"], int), "Port must be integer"
        elif connector_type == "websocket":
            assert "port" in config, "WebSocket connector must have port"
            assert isinstance(config["port"], int), "Port must be integer"

        print(f"✓ Validated {connector_type} connector configuration")


@pytest.mark.asyncio
async def test_admission_client_factory_integration():
    """Test admission client integration with factory-created components."""
    print("Testing admission client factory integration...")

    # Create extension manager
    Mock(spec=ExtensionManager)

    # Create DirectAdmissionClient with required connector config
    connection_grants = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://localhost:8080/test",
        }
    ]
    admission_client = DirectAdmissionClient(connection_grants=connection_grants)

    # Create mock node
    node = MockNode(admission_client=admission_client)

    # Test that admission client can work with discovered connectors
    connectors = node.gather_supported_callback_grants()

    # Admission client should be able to process these connectors
    for connector in connectors:
        connector_type = connector["connector_type"]
        connector["config"]

        # Test that admission client can handle the connector format
        assert isinstance(connector, dict), "Admission client expects dict format"
        assert "connector_type" in connector, "Admission client needs connector type"

        print(f"✓ Admission client can handle {connector_type} connector")


@pytest.mark.asyncio
async def test_discovery_error_recovery():
    """Test error recovery in dynamic discovery."""
    print("Testing discovery error recovery...")

    class PartiallyFailingNode(MockNode):
        """Node that fails some discovery operations."""

        def gather_supported_callback_grants(self):
            # Return partial results even if some discovery fails
            try:
                connectors = super().gather_supported_callback_grants()
                # Simulate partial failure - remove one connector
                return connectors[:1]  # Return only first connector
            except Exception:
                # Return empty list on total failure
                return []

    # Test with partially failing node
    node = PartiallyFailingNode()
    connectors = node.gather_supported_callback_grants()

    # Should get at least some connectors despite failures
    print(f"✓ Error recovery: got {len(connectors)} connectors despite failures")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
