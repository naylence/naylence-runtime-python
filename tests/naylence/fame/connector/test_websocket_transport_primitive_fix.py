#!/usr/bin/env python3
"""Test WebSocket transport primitive fix."""

import asyncio
from unittest.mock import Mock

import pytest

from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import (
    WebSocketConnectorConfig,
    WebSocketConnectorFactory,
)


@pytest.mark.asyncio
async def test_exact_failure_scenario():
    """Test the exact scenario that was causing 'Invalid configuration' error."""
    print("🧪 Testing exact WebSocket connector creation scenario...")

    # This is exactly what the WebSocket listener was doing
    connector_config = WebSocketConnectorConfig()  # Empty config
    factory = WebSocketConnectorFactory()
    mock_websocket = Mock()  # Mock WebSocket transport primitive

    # This was failing with "Invalid configuration" before our fix
    connector = await factory.create(
        config=connector_config,
        websocket=mock_websocket,  # This parameter was being ignored
    )

    print("✅ WebSocket connector created successfully!")
    print(f"   - Config: {connector_config}")
    print(f"   - Transport primitive: {mock_websocket}")
    print(f"   - Resulting connector: {connector}")

    assert connector is not None
    assert isinstance(connector, WebSocketConnector)

    return True


@pytest.mark.asyncio
async def test_websocket_websocket_fix():
    """Test that Sentinel.create_origin_connector properly passes websocket."""
    print("🧪 Testing WebSocket transport primitive fix...")

    from unittest.mock import patch

    from naylence.fame.core import DeliveryOriginType
    from naylence.fame.sentinel.sentinel import Sentinel

    # Create a minimal Sentinel instance (this might fail due to dependencies)
    # We're primarily testing the method signature and parameter passing
    sentinel = Sentinel.__new__(Sentinel)  # Create without __init__

    # Mock required attributes
    sentinel._route_manager = Mock()
    sentinel._route_manager._pending_routes = {}
    sentinel._route_manager._pending_route_metadata = {}
    sentinel._ALLOWED_BEFORE_ATTACH = set()

    # Mock the deliver method
    async def mock_deliver(env, context):
        pass

    sentinel.deliver = mock_deliver

    # Test configuration
    config = WebSocketConnectorConfig()
    mock_websocket = Mock()  # Mock WebSocket transport primitive
    system_id = "test-system-id"

    # Mock the create_resource function to capture the call
    captured_kwargs = {}

    async def mock_create_resource(factory_type, config_arg, **kwargs):
        nonlocal captured_kwargs
        print(
            f"mock_create_resource called with factory_type={factory_type}, "
            f"config_arg={config_arg}, kwargs={kwargs}"
        )
        captured_kwargs.update(kwargs)
        # Return a mock connector
        mock_connector = Mock(spec=WebSocketConnector)
        mock_connector.start = Mock(return_value=asyncio.Future())
        mock_connector.start.return_value.set_result(None)
        return mock_connector

    # Use patch to mock create_resource at the module level
    with patch("naylence.fame.sentinel.sentinel.create_resource", mock_create_resource):
        # Test the method
        await sentinel.create_origin_connector(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            system_id=system_id,
            connector_config=config,
            websocket=mock_websocket,
        )

        # Verify that websocket was passed through
        assert "websocket" in captured_kwargs, (
            f"websocket was not passed to create_resource. Captured kwargs: {captured_kwargs}"
        )
        assert captured_kwargs["websocket"] is mock_websocket, "websocket value was not preserved"

        print("✅ Transport primitive successfully passed through Sentinel.create_origin_connector")
        print(f"   - Captured kwargs: {list(captured_kwargs.keys())}")
        print(f"   - websocket value preserved: {captured_kwargs['websocket'] is mock_websocket}")

        return True


@pytest.mark.asyncio
async def test_websocket_connector_factory_with_websocket():
    """Test that WebSocketConnectorFactory works correctly with websocket."""
    print("\n🧪 Testing WebSocketConnectorFactory with websocket...")

    factory = WebSocketConnectorFactory()
    config = WebSocketConnectorConfig()
    mock_websocket = Mock()  # Mock WebSocket transport primitive

    # Test the factory directly
    connector = await factory.create(config, mock_websocket)

    assert connector is not None, "Factory should return a connector"
    assert isinstance(connector, WebSocketConnector), f"Expected WebSocketConnector, got {type(connector)}"

    print("✅ WebSocketConnectorFactory successfully creates connector with websocket")
    print(f"   - Connector type: {type(connector)}")

    return True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
