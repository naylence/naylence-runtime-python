#!/usr/bin/env python3
"""
Test script for the WebSocketListener with embedded Uvicorn server.

This script demonstrates how the WebSocket listener integrates with node lifecycle
and provides WebSocket attach endpoints for WebSocket connectors.
"""

import asyncio

from naylence.fame.connector.websocket_listener import WebSocketListener
from naylence.fame.connector.websocket_listener_factory import (
    WebSocketListenerConfig,
    WebSocketListenerFactory,
)
from naylence.fame.security.auth.noop_token_verifier import NoopTokenVerifier


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self.system_id = "test-node"
        self.physical_path = "test-path"
        self.security_manager = None
        self.public_url = "http://localhost"


async def test_websocket_listener_lifecycle():
    """Test that the WebSocket listener starts and stops with node lifecycle."""
    print("Testing WebSocketListener lifecycle...")

    # Create factory and config
    factory = WebSocketListenerFactory()
    config = WebSocketListenerConfig(
        host="127.0.0.1",
        port=0,  # Let OS choose port
    )

    # Create listener
    listener = await factory.create(config=config)

    # Create mock node
    mock_node = MockNode()

    try:
        # Test listener starts on node initialization
        await listener.on_node_initialized(mock_node)

        print("✓ WebSocket listener started successfully!")
        print(f"✓ WebSocket listener base URL: {listener.base_url}")
        print(f"✓ WebSocket listener advertised host: {listener.advertised_host}")
        print(f"✓ WebSocket listener advertised port: {listener.advertised_port}")
        print(f"✓ WebSocket listener is running: {listener.is_running}")

        # Test node started event
        await listener.on_node_started(mock_node)
        print("✓ Node started event handled")

        # Verify connector descriptor
        descriptor = listener.get_connector_descriptor()
        assert descriptor is not None
        assert descriptor["type"] == "WebSocketListener"
        print(f"✓ Connector descriptor: {descriptor}")

        # Test router creation
        router = await listener.create_router()
        assert router is not None
        print("✓ Router created successfully")

        # Test with custom token verifier
        custom_verifier = NoopTokenVerifier()
        WebSocketListener(http_server=listener.http_server, token_verifier=custom_verifier)
        print("✓ Custom token verifier WebSocket listener created")

    finally:
        # Test listener stops on node stopped
        await listener.on_node_stopped(mock_node)
        print("✓ WebSocket listener stopped successfully!")


async def test_listener_config():
    """Test WebSocket listener configuration."""
    print("\nTesting WebSocketListener configuration...")

    config = WebSocketListenerConfig(
        host="0.0.0.0",
        port=9999,
    )

    assert config.type == "WebSocketListener"
    assert config.host == "0.0.0.0"
    assert config.port == 9999

    print("✓ WebSocketListener configuration validated")


if __name__ == "__main__":

    async def run_tests():
        print("=" * 60)
        print("WebSocket Listener Test Suite")
        print("=" * 60)

        await test_websocket_listener_lifecycle()
        await test_listener_config()

        print("\n" + "=" * 60)
        print("All WebSocket listener tests passed! 🎉")
        print("=" * 60)

    asyncio.run(run_tests())
