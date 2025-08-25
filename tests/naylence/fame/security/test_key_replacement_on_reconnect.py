#!/usr/bin/env python3

"""
Test script to verify that stale keys are removed when a system reconnects.
"""

import logging

import pytest

from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_key_replacement_on_reconnect():
    """Test that old keys are removed when new keys are added for the same path."""

    key_store = InMemoryKeyStore()

    # Simulate first client connection with initial keys
    physical_path = "/w3YI3dnHsQnuENw/mksnrwhAGPX8Rxn"
    initial_keys = [
        {
            "x": "9Wslt4e9KnOBh4nafwG39hOeuKMLHW5jQ9fApWHUgqk",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "5IrhN337S25OqJK",  # Old key ID from first run
            "alg": "EdDSA",
            "use": "sig",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "OUN06llYA1Vd5DprpjAMvyVwveQMANZMDfXFh_1qHnI",
            "kid": "UZZyOVSQaEAgr0E",  # Old key ID from first run
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    print("=== Initial client connection ===")
    await key_store.add_keys(initial_keys, physical_path=physical_path)

    keys_after_initial = list(await key_store.get_keys_for_path(physical_path))
    print(f"Keys after initial connection: {[k['kid'] for k in keys_after_initial]}")
    print(f"Total keys in store: {len(list(await key_store.get_keys()))}")

    # Simulate client reconnection with new keys (like what happens on restart)
    new_keys = [
        {
            "x": "different_signature_key_material",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "8xsGjFicd5zC5Xy",  # New key ID from second run
            "alg": "EdDSA",
            "use": "sig",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "different_encryption_key_material",
            "kid": "B2fNN2MPxFYI6IJ",  # New key ID from second run
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    print("\n=== Client reconnection ===")
    print("Removing old keys...")
    removed_count = await key_store.remove_keys_for_path(physical_path)
    print(f"Removed {removed_count} old keys")

    print("Adding new keys...")
    await key_store.add_keys(new_keys, physical_path=physical_path)

    keys_after_reconnect = list(await key_store.get_keys_for_path(physical_path))
    print(f"Keys after reconnection: {[k['kid'] for k in keys_after_reconnect]}")
    print(f"Total keys in store: {len(list(await key_store.get_keys()))}")

    # Verify old keys are gone and new keys are present
    all_key_ids = [k["kid"] for k in await key_store.get_keys()]

    old_key_ids = {"5IrhN337S25OqJK", "UZZyOVSQaEAgr0E"}
    new_key_ids = {"8xsGjFicd5zC5Xy", "B2fNN2MPxFYI6IJ"}

    old_keys_still_present = old_key_ids.intersection(set(all_key_ids))
    new_keys_present = new_key_ids.intersection(set(all_key_ids))

    print("\n=== Verification ===")
    print(f"Old keys still present: {old_keys_still_present}")
    print(f"New keys present: {new_keys_present}")

    success = len(old_keys_still_present) == 0 and len(new_keys_present) == 2 and len(all_key_ids) == 2

    return success
