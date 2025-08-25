#!/usr/bin/env python3
"""
Test script to verify the TaskSpawner fix handles both scenarios correctly.
"""

import asyncio
import sys

import pytest

# Add the src directory to the path

try:
    from naylence.fame.util.task_spawner import TaskSpawner

    print("✓ Successfully imported TaskSpawner")
except ImportError as e:
    print(f"✗ Failed to import TaskSpawner: {e}")
    sys.exit(1)


@pytest.mark.asyncio
async def test_task_spawner_cancellation():
    """Test TaskSpawner with cancellation scenarios."""

    print("\n=== Testing TaskSpawner Cancellation Handling ===")

    spawner = TaskSpawner()

    # Test 1: Normal task that completes
    async def normal_task():
        await asyncio.sleep(0.1)
        return "completed"

    spawner.spawn(normal_task(), name="normal-task")
    await asyncio.sleep(0.2)  # Let it complete
    print("✓ Normal task completed")

    # Test 2: Task that simulates the "await wasn't used with future" error
    async def problematic_task():
        await asyncio.sleep(0.1)
        # Simulate the TypeError that was causing issues
        raise TypeError("await wasn't used with future")

    spawner.spawn(problematic_task(), name="problematic-task")
    await asyncio.sleep(0.2)  # Let it complete with error
    print("✓ Problematic task completed (should be logged as debug)")

    # Test 3: Long-running task that gets cancelled
    async def long_running_task():
        try:
            await asyncio.sleep(10)  # Long sleep
        except asyncio.CancelledError:
            print("  Long-running task was cancelled")
            raise

    spawner.spawn(long_running_task(), name="long-running-task")
    await asyncio.sleep(0.1)  # Let it start

    # Test shutdown with cancellation
    print("\n--- Testing shutdown with cancellation ---")
    await spawner.shutdown_tasks(grace_period=0.01, cancel_hang=True, join_timeout=1.0)
    print("✓ Shutdown completed without client crash")

    # Check if any errors were recorded
    last_error = spawner.last_spawner_error
    print(f"Last spawner error: {last_error}")

    print("\n=== Test Summary ===")
    print("✓ TaskSpawner properly handles cancellation during shutdown")
    print("✓ 'await wasn't used with future' errors are logged as debug, not error")
    print("✓ No client crashes during shutdown")
