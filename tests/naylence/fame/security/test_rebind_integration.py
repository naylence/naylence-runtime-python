#!/usr/bin/env python3
"""
Integration test for stale key removal with node rebinding scenario.
This test verifies the end-to-end behavior when a child node rebinds to a parent.
"""

import pytest

# Add the core package to the path
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore


def create_test_key(kid: str, physical_path: str) -> dict:
    """Create a test X25519 encryption key."""
    return {
        "kid": kid,
        "kty": "OKP",
        "crv": "X25519",
        "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",  # Private key for encryption
        "physical_path": physical_path,
        "use": "enc",
    }


@pytest.mark.asyncio
async def test_node_rebind_scenario():
    """Test the node rebind scenario that was causing stale key issues."""
    print("Testing node rebind scenario with stale key removal...")

    # Create key store
    key_store = InMemoryKeyStore()

    # Simulate the problematic scenario:
    # 1. Child node binds to parent with key_id_1
    # 2. Child node rebinds to parent with key_id_2
    # 3. Parent should only have key_id_2 for the child path

    child_path = "/child/node"

    # Step 1: Initial binding
    initial_kid = "child_key_v1"
    initial_key = create_test_key(initial_kid, child_path)
    await key_store.add_key(initial_kid, initial_key)

    print(f"Step 1: Child bound with {initial_kid}")
    print(f"Keys for child path: {[k['kid'] for k in await key_store.get_keys_for_path(child_path)]}")

    # Verify initial state
    assert await key_store.has_key(initial_kid), "Initial key should exist"
    child_keys = list(await key_store.get_keys_for_path(child_path))
    assert len(child_keys) == 1, "Should have exactly 1 key for child"
    assert child_keys[0]["kid"] == initial_kid, "Should be the initial key"

    # Step 2: Child rebinds with new key
    rebind_kid = "child_key_v2"
    rebind_key = create_test_key(rebind_kid, child_path)
    await key_store.add_key(rebind_kid, rebind_key)

    print(f"Step 2: Child rebound with {rebind_kid}")
    print(f"Keys for child path: {[k['kid'] for k in await key_store.get_keys_for_path(child_path)]}")

    # Step 3: Verify stale key removal
    assert not await key_store.has_key(initial_kid), f"Stale key {initial_kid} should be removed"
    assert await key_store.has_key(rebind_kid), f"New key {rebind_kid} should exist"

    child_keys = list(await key_store.get_keys_for_path(child_path))
    assert len(child_keys) == 1, f"Should have exactly 1 key for child, got {len(child_keys)}"
    assert child_keys[0]["kid"] == rebind_kid, f"Should be the new key, got {child_keys[0]['kid']}"

    print("✓ Node rebind scenario test passed!")

    # Test multiple rebinds
    print("\nTesting multiple rebinds...")

    for i in range(3, 6):  # Rebind 3 more times
        new_kid = f"child_key_v{i}"
        new_key = create_test_key(new_kid, child_path)
        await key_store.add_key(new_kid, new_key)

        # Verify only the latest key exists
        child_keys = list(await key_store.get_keys_for_path(child_path))
        assert len(child_keys) == 1, f"Should have exactly 1 key after rebind {i}"
        assert child_keys[0]["kid"] == new_kid, f"Should be the latest key after rebind {i}"

        print(f"  Rebind {i}: Now using {new_kid}")

    print("✓ Multiple rebinds test passed!")


@pytest.mark.asyncio
async def test_concurrent_keys_different_paths():
    """Test that keys for different paths don't interfere."""
    print("\nTesting concurrent keys for different paths...")

    key_store = InMemoryKeyStore()

    # Add keys for multiple child nodes
    children = ["/child1", "/child2", "/child3"]

    for i, child_path in enumerate(children, 1):
        kid = f"child{i}_key"
        key = create_test_key(kid, child_path)
        await key_store.add_key(kid, key)

    # Verify all keys exist
    for i, child_path in enumerate(children, 1):
        kid = f"child{i}_key"
        assert await key_store.has_key(kid), f"Key for child{i} should exist"

        child_keys = list(await key_store.get_keys_for_path(child_path))
        assert len(child_keys) == 1, f"Child{i} should have exactly 1 key"
        assert child_keys[0]["kid"] == kid, f"Child{i} should have the correct key"

    # Rebind child2 and verify others are unaffected
    child2_new_kid = "child2_key_v2"
    child2_new_key = create_test_key(child2_new_kid, "/child2")
    await key_store.add_key(child2_new_kid, child2_new_key)

    # Child1 and Child3 should be unaffected
    assert await key_store.has_key("child1_key"), "Child1 key should still exist"
    assert await key_store.has_key("child3_key"), "Child3 key should still exist"
    assert not await key_store.has_key("child2_key"), "Old Child2 key should be removed"
    assert await key_store.has_key(child2_new_kid), "New Child2 key should exist"

    print("✓ Concurrent keys for different paths test passed!")
