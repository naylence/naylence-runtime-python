#!/usr/bin/env python3

"""
Simple test of the key replacement functionality that caused the user's issue.
"""

import logging

import pytest

from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_simple_key_replacement():
    """Test the simple key replacement that fixes the user's issue."""

    print("🧪 Testing simple key replacement scenario...")

    key_store = InMemoryKeyStore()

    client_physical_path = "/w3YI3dnHsQnuENw/mksnrwhAGPX8Rxn"

    # === Add initial keys (first client run) ===
    print("\n📱 First client run - adding initial keys...")

    first_keys = [
        {
            "x": "9Wslt4e9KnOBh4nafwG39hOeuKMLHW5jQ9fApWHUgqk",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "5IrhN337S25OqJK",  # First run key IDs
            "alg": "EdDSA",
            "use": "sig",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "OUN06llYA1Vd5DprpjAMvyVwveQMANZMDfXFh_1qHnI",
            "kid": "UZZyOVSQaEAgr0E",  # The problematic old encryption key
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    await key_store.add_keys(first_keys, physical_path=client_physical_path)

    initial_keys = list(await key_store.get_keys_for_path(client_physical_path))
    print(f"✅ Initial keys: {[k['kid'] for k in initial_keys]}")

    # Verify the problematic key exists
    has_old_encryption_key = await key_store.has_key("UZZyOVSQaEAgr0E")
    print(f"🔑 Old encryption key (UZZyOVSQaEAgr0E) exists: {has_old_encryption_key}")

    # === Client restart scenario ===
    print("\n🔄 Client restart - this is where the old key becomes stale...")

    # Remove old keys (what our fix does)
    removed_count = await key_store.remove_keys_for_path(client_physical_path)
    print(f"🗑️  Removed {removed_count} stale keys")

    # Add new keys (second client run)
    second_keys = [
        {
            "x": "different_signature_key_material_2nd_run",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "8xsGjFicd5zC5Xy",  # Second run key IDs
            "alg": "EdDSA",
            "use": "sig",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "different_encryption_key_material_2nd_run",
            "kid": "B2fNN2MPxFYI6IJ",  # New encryption key
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    await key_store.add_keys(second_keys, physical_path=client_physical_path)

    new_keys = list(await key_store.get_keys_for_path(client_physical_path))
    print(f"✅ New keys: {[k['kid'] for k in new_keys]}")

    # === Test the specific scenario that was failing ===
    print("\n🎯 Testing the specific failure scenario...")

    # This was the failing scenario: agent tries to decrypt with old key
    has_old_encryption_key_after = await key_store.has_key("UZZyOVSQaEAgr0E")
    has_new_encryption_key = await key_store.has_key("B2fNN2MPxFYI6IJ")

    print("🔍 Key lookup results:")
    print(f"   Old encryption key (UZZyOVSQaEAgr0E) still exists: {has_old_encryption_key_after}")
    print(f"   New encryption key (B2fNN2MPxFYI6IJ) exists: {has_new_encryption_key}")

    # Test if we would get the original error
    if has_old_encryption_key_after:
        print("❌ WOULD STILL FAIL: Old encryption key still exists")
        print("   Agent would still try to use UZZyOVSQaEAgr0E")
        print("   Error: 'Failed to find key UZZyOVSQaEAgr0E' would still occur")
        success = False
    else:
        print("✅ FIXED: Old encryption key is gone")
        if has_new_encryption_key:
            print("✅ WORKING: New encryption key is available")
            print("   Agent will now use B2fNN2MPxFYI6IJ for decryption")
            print("   No more 'Unknown key id' errors!")
            success = True
        else:
            print("❌ ISSUE: New encryption key not found")
            success = False

    # Summarize all keys in the store
    all_keys = list(await key_store.get_keys())
    print("\n📊 Final key store state:")
    print(f"   Total keys: {len(all_keys)}")
    print(f"   Key IDs: {[k['kid'] for k in all_keys]}")

    # Add proper assertions
    assert not has_old_encryption_key_after, "Old encryption key should be removed after client reconnect"
    assert has_new_encryption_key, "New encryption key should be available after client reconnect"
    assert success, "Key replacement should succeed"

    # Verify expected keys are present
    expected_new_keys = {"B2fNN2MPxFYI6IJ", "8xsGjFicd5zC5Xy"}
    actual_key_ids = {k["kid"] for k in all_keys}
    assert expected_new_keys.issubset(
        actual_key_ids
    ), f"Expected keys {expected_new_keys} should be in store"

    # Verify old key is not present
    assert "UZZyOVSQaEAgr0E" not in actual_key_ids, "Old encryption key should not be in store"
