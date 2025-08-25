#!/usr/bin/env python3
"""
Test stale key removal functionality in InMemoryKeyStore.
This test verifies that when a node rebinds with new keys, stale keys for the same path/use are removed.
"""

import pytest

from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore


def create_test_jwk(kid: str, physical_path: str, use: str = "enc") -> dict:
    """Create a minimal JWK for testing."""
    if use == "sig":
        # Use Ed25519 for signing
        return {
            "kid": kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",  # Valid Ed25519 public key
            "physical_path": physical_path,
            "use": use,
        }
    else:
        # Use X25519 for encryption
        return {
            "kid": kid,
            "kty": "OKP",
            "crv": "X25519",
            "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",  # Valid X25519 public key
            "physical_path": physical_path,
            "use": use,
        }


@pytest.mark.asyncio
async def test_stale_key_removal():
    """Test that adding a new key removes stale keys for the same path and use."""
    key_store = InMemoryKeyStore()

    # Scenario: A child node initially binds with key_id_1
    physical_path = "/child/node/path"
    old_kid = "key_id_1"
    new_kid = "key_id_2"

    # Create JWKs for testing
    old_jwk = create_test_jwk(old_kid, physical_path)
    new_jwk = create_test_jwk(new_kid, physical_path)

    # Add first key
    await key_store.add_key(old_kid, old_jwk)

    # Verify it exists
    print(f"Key store has key {old_kid}: {await key_store.has_key(old_kid)}")

    # Add a new key for the same path (which should replace the old one)
    await key_store.add_key(new_kid, new_jwk)

    # Verify stale key was removed
    assert not await key_store.has_key(old_kid), f"Stale key {old_kid} should have been removed"
    assert await key_store.has_key(new_kid), f"New key {new_kid} should be present"

    # Verify only the new key exists for this path
    keys_for_path = list(await key_store.get_keys_for_path(physical_path))
    assert len(keys_for_path) == 1, f"Expected 1 key for path, got {len(keys_for_path)}"
    assert keys_for_path[0]["kid"] == new_kid, f"Expected new key, got {keys_for_path[0]['kid']}"

    print("✓ Stale key removal test passed!")


@pytest.mark.asyncio
async def test_different_use_keys_coexist():
    """Test that keys with different 'use' values can coexist for the same path."""
    key_store = InMemoryKeyStore()

    physical_path = "/node/path"
    enc_kid = "enc_key"
    sig_kid = "sig_key"

    # Add encryption key
    enc_jwk = create_test_jwk(enc_kid, physical_path, "enc")
    await key_store.add_key(enc_kid, enc_jwk)

    # Add signing key (different use)
    sig_jwk = create_test_jwk(sig_kid, physical_path, "sig")
    await key_store.add_key(sig_kid, sig_jwk)

    # Both keys should exist
    assert await key_store.has_key(enc_kid), "Encryption key should exist"
    assert await key_store.has_key(sig_kid), "Signing key should exist"

    # Verify both keys are returned for the path
    keys_for_path = list(await key_store.get_keys_for_path(physical_path))
    assert len(keys_for_path) == 2, f"Expected 2 keys for path, got {len(keys_for_path)}"

    print("✓ Different use keys coexistence test passed!")


@pytest.mark.asyncio
async def test_different_path_keys_coexist():
    """Test that keys for different paths don't interfere with each other."""
    key_store = InMemoryKeyStore()

    path1 = "/node1/path"
    path2 = "/node2/path"
    kid1 = "key_for_node1"
    kid2 = "key_for_node2"

    # Add keys for different paths
    jwk1 = create_test_jwk(kid1, path1, "enc")
    jwk2 = create_test_jwk(kid2, path2, "enc")

    await key_store.add_key(kid1, jwk1)
    await key_store.add_key(kid2, jwk2)

    # Both keys should exist
    assert await key_store.has_key(kid1), "Key for node1 should exist"
    assert await key_store.has_key(kid2), "Key for node2 should exist"

    print("✓ Different path keys coexistence test passed!")


@pytest.mark.asyncio
async def test_no_physical_path_keys():
    """Test that keys without physical_path are not affected by stale key removal."""
    key_store = InMemoryKeyStore()

    # Add key without physical_path
    kid1 = "no_path_key1"
    jwk1 = {
        "kid": kid1,
        "kty": "OKP",
        "crv": "X25519",
        "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
        "use": "enc",
        # No physical_path
    }
    await key_store.add_key(kid1, jwk1)

    # Add another key without physical_path
    kid2 = "no_path_key2"
    jwk2 = {
        "kid": kid2,
        "kty": "OKP",
        "crv": "X25519",
        "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
        "use": "enc",
        # No physical_path
    }
    await key_store.add_key(kid2, jwk2)

    # Both keys should exist (no stale key removal without physical_path)
    assert await key_store.has_key(kid1), "First key without path should exist"
    assert await key_store.has_key(kid2), "Second key without path should exist"

    print("✓ No physical_path keys test passed!")
