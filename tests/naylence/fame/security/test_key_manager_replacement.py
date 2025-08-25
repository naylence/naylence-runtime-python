#!/usr/bin/env python3

"""
Direct test of the key replacement logic in the key manager.
"""

import logging
from typing import Optional

import pytest

from naylence.fame.core import DeliveryOriginType, FameDeliveryContext, FameEnvelope
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_key_manager_replacement():
    """Test the key manager's key replacement functionality."""

    print("🧪 Testing DefaultKeyManager key replacement...")

    key_store = InMemoryKeyStore()

    # Create a mock node for the new interface
    class MockNode:
        def __init__(self):
            self._id = "test_system"
            self._sid = "test_sid"
            self.physical_path = "/w3YI3dnHsQnuENw"  # Parent path
            self._has_parent = False
            self._envelope_factory = MockEnvelopeFactory()

        @property
        def has_parent(self) -> bool:
            """Property to match the NodeLike interface."""
            return self._has_parent

        async def forward_upstream(
            self, env: FameEnvelope, context: Optional[FameDeliveryContext] = None
        ) -> None:
            pass

    class MockEnvelopeFactory:
        def create_envelope(self, **kwargs) -> FameEnvelope:
            from naylence.fame.core import DataFrame, create_fame_envelope

            return create_fame_envelope(frame=DataFrame(payload={}))

    # Create key manager with new simplified interface
    key_manager = DefaultKeyManager(key_store=key_store)

    # Create mock node and initialize context
    mock_node = MockNode()
    await key_manager.on_node_started(mock_node)

    client_system_id = "mksnrwhAGPX8Rxn"
    client_physical_path = f"/w3YI3dnHsQnuENw/{client_system_id}"

    # === First connection keys ===
    print("\n📱 Adding initial client keys...")

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
            "kid": "UZZyOVSQaEAgr0E",  # First run key IDs
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    await key_manager.add_keys(
        keys=first_keys,
        physical_path=client_physical_path,
        system_id=client_system_id,
        origin=DeliveryOriginType.DOWNSTREAM,
    )

    initial_keys = list(await key_store.get_keys_for_path(client_physical_path))
    print(f"✅ Initial keys: {[k['kid'] for k in initial_keys]}")

    # === Simulate client restart ===
    print("\n🔄 Client restart - removing old keys...")

    removed_count = await key_manager.remove_keys_for_path(client_physical_path)
    print(f"🗑️  Removed {removed_count} old keys")

    # === Add new connection keys ===
    print("\n📱 Adding new client keys...")

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
            "kid": "B2fNN2MPxFYI6IJ",  # Second run key IDs
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    await key_manager.add_keys(
        keys=second_keys,
        physical_path=client_physical_path,
        system_id=client_system_id,
        origin=DeliveryOriginType.DOWNSTREAM,
    )

    # === Verify results ===
    print("\n🔍 Verifying key replacement...")

    current_keys = list(await key_store.get_keys_for_path(client_physical_path))
    all_key_ids = [k["kid"] for k in await key_store.get_keys()]

    old_key_ids = {"5IrhN337S25OqJK", "UZZyOVSQaEAgr0E"}
    new_key_ids = {"8xsGjFicd5zC5Xy", "B2fNN2MPxFYI6IJ"}

    old_keys_still_present = old_key_ids.intersection(set(all_key_ids))
    new_keys_present = new_key_ids.intersection(set(all_key_ids))

    print(f"Current keys for path: {[k['kid'] for k in current_keys]}")
    print(f"All keys in store: {all_key_ids}")
    print(f"Old keys still present: {old_keys_still_present}")
    print(f"New keys present: {new_keys_present}")

    # Test key lookup for problematic scenario
    old_encryption_key_gone = not await key_manager.has_key("UZZyOVSQaEAgr0E")
    new_encryption_key_present = await key_manager.has_key("B2fNN2MPxFYI6IJ")

    print("\n🎯 Key lookup verification:")
    print(f"   Old encryption key (UZZyOVSQaEAgr0E) gone: {old_encryption_key_gone}")
    print(f"   New encryption key (B2fNN2MPxFYI6IJ) present: {new_encryption_key_present}")

    success = (
        old_encryption_key_gone
        and new_encryption_key_present
        and len(old_keys_still_present) == 0
        and len(new_keys_present) == 2
    )

    if success:
        print("\n🎉 SUCCESS: Key manager replacement works correctly!")
        print("   - The 'Failed to find key UZZyOVSQaEAgr0E' error should be fixed")
        print("   - Agent will now use the new encryption key B2fNN2MPxFYI6IJ")
    else:
        print("\n❌ FAILURE: Key manager replacement didn't work as expected")

    return success
