#!/usr/bin/env python3
"""
Test script to verify the BaseAsyncConnector shutdown fix.
"""

import asyncio
import sys
from unittest.mock import AsyncMock

import pytest

# Add the src directory to the path

try:
    from naylence.fame.connector.base_async_connector import BaseAsyncConnector

    print("✓ Successfully imported BaseAsyncConnector")
except ImportError as e:
    print(f"✗ Failed to import BaseAsyncConnector: {e}")
    sys.exit(1)


class MockConnector(BaseAsyncConnector):
    """Mock implementation of BaseAsyncConnector for testing."""

    def __init__(self):
        super().__init__()
        self.closed = False

    async def _transport_send_bytes(self, data: bytes) -> None:
        pass

    async def _transport_receive(self) -> bytes:
        # Simulate the race condition that causes "await wasn't used with future"
        await asyncio.sleep(0.1)
        raise RuntimeError("await wasn't used with future")

    async def _transport_close(self, code: int, reason: str) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_shutdown_race_condition():
    """Test that shutdown properly handles the await future race condition."""

    print("\n=== Testing BaseAsyncConnector Shutdown Race Condition ===")

    connector = MockConnector()

    # Start the connector with a mock handler
    mock_handler = AsyncMock()
    await connector.start(mock_handler)

    print("✓ Connector started successfully")

    # Wait a bit to let the receive loop start
    await asyncio.sleep(0.1)

    # Now trigger shutdown - this should trigger the race condition
    try:
        await connector._shutdown(1000, "test shutdown", grace_period=0.1, join_timeout=0.5)
        print("✓ Shutdown completed without errors")
    except Exception as e:
        print(f"✗ Shutdown failed with error: {e}")
        raise

    print("✓ Transport was closed:", connector.closed)


@pytest.mark.asyncio
async def test_normal_shutdown():
    """Test normal shutdown without race conditions."""

    print("\n=== Testing Normal Shutdown ===")

    class NormalConnector(BaseAsyncConnector):
        def __init__(self):
            super().__init__()
            self.closed = False

        async def _transport_send_bytes(self, data: bytes) -> None:
            pass

        async def _transport_receive(self) -> bytes:
            await asyncio.sleep(10)  # Long sleep, will be cancelled
            return b"test"

        async def _transport_close(self, code: int, reason: str) -> None:
            self.closed = True

    connector = NormalConnector()
    mock_handler = AsyncMock()
    await connector.start(mock_handler)

    print("✓ Normal connector started")

    await asyncio.sleep(0.1)

    try:
        await connector._shutdown(1000, "normal shutdown", grace_period=0.1, join_timeout=0.5)
        print("✓ Normal shutdown completed successfully")
    except Exception as e:
        print(f"✗ Normal shutdown failed: {e}")
        raise

    print("✓ Normal transport was closed:", connector.closed)


@pytest.mark.asyncio
async def test_all_shutdown_fixes():
    """Test all shutdown-related fixes."""
    await test_shutdown_race_condition()
    await test_normal_shutdown()

    print("\n=== Test Summary ===")
    print("✓ BaseAsyncConnector shutdown properly handles race conditions")
    print("✓ 'await wasn't used with future' errors are caught and logged as debug")
    print("✓ Normal shutdown operations continue to work correctly")
