"""
Test script to verify HttpStatelessConnector shutdown behavior.
"""

import asyncio
import logging

from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector

# Set up logging to see what's happening
logging.basicConfig(level=logging.DEBUG)


async def test_shutdown():
    """Test that HttpStatelessConnector shuts down quickly."""

    # Create a connector
    connector = HttpStatelessConnector(
        url="http://localhost:9999/test",  # Non-existent URL is fine for this test
        max_queue=10,
    )

    # Mock handler that just prints received envelopes
    async def mock_handler(envelope, context):
        print(f"Received: {envelope.id}")

    print("Starting connector...")
    await connector.start(mock_handler)

    # Add some test data to the receive queue
    test_data = b'{"test": "data"}'
    await connector.push_to_receive(test_data)

    # Give it a moment to process
    await asyncio.sleep(0.1)

    print("Stopping connector...")
    start_time = asyncio.get_event_loop().time()

    # Stop the connector
    await connector.stop()

    stop_time = asyncio.get_event_loop().time()
    shutdown_duration = stop_time - start_time

    print(f"Shutdown completed in {shutdown_duration:.3f} seconds")

    # Verify it shut down quickly (should be well under 1 second)
    if shutdown_duration > 1.0:
        print(f"❌ SLOW SHUTDOWN: {shutdown_duration:.3f}s > 1.0s")
        return False
    else:
        print(f"✅ FAST SHUTDOWN: {shutdown_duration:.3f}s")
        return True


if __name__ == "__main__":
    result = asyncio.run(test_shutdown())
    exit(0 if result else 1)
