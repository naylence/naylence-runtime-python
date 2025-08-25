import asyncio

import httpx

from naylence.fame.connector.http_listener_factory import (
    HttpListenerConfig,
    HttpListenerFactory,
)
from naylence.fame.core import FameEnvelope, NodeAttachFrame


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self.system_id = "test-node"
        self.public_url = None  # Let the listener use the actual server URL


async def test_http_listener_lifecycle():
    """Test that the HTTP listener starts and stops with node lifecycle."""
    print("Testing HttpListener lifecycle...")

    # Create factory and config
    factory = HttpListenerFactory()
    config = HttpListenerConfig(
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

        print("✓ HTTP listener started successfully!")
        # print(f"  Listening on: {listener.advertised_host}:{listener.advertised_port}")
        print(f"  Base URL: {listener.base_url}")
        print(f"  Is running: {listener.is_running}")

        # Test health check endpoint
        async with httpx.AsyncClient() as client:
            health_url = f"{listener.base_url}/fame/v1/ingress/health"
            print(f"Testing health check: {health_url}")

            response = await client.get(health_url)
            print(f"✓ Health check response: {response.status_code}")
            print(f"  Content: {response.json()}")

            # Test downstream endpoint with NodeAttach frame
            downstream_url = f"{listener.base_url}/fame/v1/ingress/downstream/test-child"
            print(f"Testing downstream ingress: {downstream_url}")

            # Create a simple test frame
            test_frame = NodeAttachFrame(
                system_id="test-child",
                instance_id="test-instance",
                supported_inbound_connectors=[],
            )
            test_envelope = FameEnvelope(frame=test_frame)
            test_data = test_envelope.model_dump_json().encode("utf-8")

            response = await client.post(
                downstream_url,
                content=test_data,
                headers={"Content-Type": "application/octet-stream"},
            )
            print(f"✓ Downstream ingress response: {response.status_code}")
            print(f"  Content: {response.json()}")

    finally:
        # Test listener stops on node stop
        await listener.on_node_stopped(mock_node)
        print("✓ HTTP listener stopped successfully!")


async def test_listener_config():
    """Test HTTP listener configuration."""
    print("\nTesting HTTP listener configuration...")

    factory = HttpListenerFactory()

    # Find an available port
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        available_port = s.getsockname()[1]

    # Test with explicit config
    config = HttpListenerConfig(
        type="HttpListener",
        host="127.0.0.1",
        port=available_port,  # Use available port
    )

    await factory.create(config=config)
    print("✓ Created listener with config:")
    print(f"  Type: {config.type}")
    print(f"  Host: {config.host}")
    print(f"  Port: {config.port}")

    # Test with no config (defaults)
    await factory.create()
    print("✓ Created listener with defaults")


async def main():
    """Run all tests."""
    print("=" * 60)
    print("HttpListener Test Suite")
    print("=" * 60)

    try:
        await test_http_listener_lifecycle()
        await test_listener_config()

        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
