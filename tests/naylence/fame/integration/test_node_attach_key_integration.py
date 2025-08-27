"""
Integration test for NodeAttach -> Key Management -> Envelope Verification flow.

This test would have caught the bug where keys added during NodeAttach were not
available to the EnvelopeVerifier, causing "Unknown key id" errors.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from naylence.fame.core import (
    AddressBindFrame,
    DeliveryOriginType,
    FameEnvelope,
)
from naylence.fame.security.crypto.providers.default_crypto_provider import (
    DefaultCryptoProvider,
)
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier
from naylence.fame.util.util import secure_digest


@pytest.mark.asyncio
async def test_node_attach_keys_available_for_envelope_verification():
    """
    Test the complete flow: NodeAttach adds keys -> EnvelopeVerifier can use them.

    This is the integration test that would have caught the "Unknown key id" bug.
    """
    print("Testing NodeAttach -> Key Management -> Envelope Verification integration...")

    # 1. Set up the global key store that should be shared between components
    global_key_store = get_key_store()

    # 2. Create a DefaultKeyManager that uses the global key store
    key_manager = DefaultKeyManager(key_store=global_key_store)

    # 3. Create an EnvelopeVerifier that should use the same global key store
    envelope_verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())  # Use explicit key provider

    # 4. Create a child node's crypto provider and keys
    child_crypto = DefaultCryptoProvider()
    child_crypto.set_node_context(
        node_id="child-node-id", physical_path="/parent/child", logicals=["fame.fabric"]
    )

    # Generate keys for the child
    child_jwks = child_crypto.get_jwks()
    child_keys = child_jwks["keys"]

    # 5. Simulate NodeAttach by adding child's keys via KeyManager
    # Use LOCAL origin to avoid the complex path validation logic
    system_id = "child-system-id"
    physical_path = "/parent/child"

    await key_manager.add_keys(
        keys=child_keys,
        sid=None,
        physical_path=physical_path,
        system_id=system_id,
        origin=DeliveryOriginType.LOCAL,  # Simplified for this test
    )

    # 6. Create a signed envelope from the child using its keys
    child_signer = EdDSAEnvelopeSigner(crypto=child_crypto)

    # Create an envelope that the child would send after NodeAttach
    frame = AddressBindFrame(
        address="test@/",
        encryption_key_id=child_keys[1]["kid"] if len(child_keys) > 1 else None,
        physical_path=physical_path,
    )
    envelope = FameEnvelope(frame=frame)

    # Set the sid before signing (required by EdDSAEnvelopeSigner)
    envelope.sid = secure_digest(physical_path)

    # Sign the envelope with the child's signing key
    signed_envelope = child_signer.sign_envelope(envelope, physical_path=physical_path)

    # 7. Verify that the EnvelopeVerifier can verify the signed envelope
    # This is where the bug would manifest: "Unknown key id"
    try:
        verification_result = await envelope_verifier.verify_envelope(signed_envelope, check_payload=False)
        assert verification_result is True, "Envelope verification should succeed"
        print("✅ Envelope verification succeeded - keys are properly shared")

    except ValueError as e:
        if "Unknown key id" in str(e):
            pytest.fail(f"BUG DETECTED: Keys added via KeyManager not available to EnvelopeVerifier: {e}")
        else:
            raise

    # 8. Additional verification: Check that keys are actually in the key store
    signing_key = child_keys[0]  # First key is typically signing key
    assert await key_manager.has_key(signing_key["kid"]), "KeyManager should have the signing key"

    # Verify the global key store has the key (this is what EnvelopeVerifier uses)
    try:
        retrieved_key = await global_key_store.get_key(signing_key["kid"])
        assert retrieved_key is not None, "Global key store should have the signing key"
        print("✅ Keys properly stored in global key store")
    except ValueError:
        pytest.fail("BUG: Key not found in global key store that EnvelopeVerifier uses")


@pytest.mark.asyncio
async def test_full_node_attach_flow_integration():
    """
    Test the complete NodeAttach flow focusing on key sharing between components.

    This simulates the exact scenario from the sentinel logs in a simplified way.
    """
    print("Testing full NodeAttach flow with key sharing...")

    # 1. Set up sentinel-side components using realistic paths
    global_key_store = get_key_store()
    key_manager = DefaultKeyManager(key_store=global_key_store)

    # Mock the routing node with realistic attributes
    mock_routing_node = MagicMock()
    mock_routing_node.physical_path = "/w3YI3dnHsQnuENw"  # From the logs
    mock_routing_node._id = "w3YI3dnHsQnuENw"

    # Initialize key manager context
    await key_manager.on_node_started(mock_routing_node)

    # Create envelope verifier that should share the same key store
    envelope_verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())

    # 2. Set up child node with keys (from the logs)
    child_crypto = DefaultCryptoProvider()
    child_crypto.set_node_context(
        node_id="OHGjVrpDX1EnhT1",
        physical_path="/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1",
        logicals=["fame.fabric"],
    )

    child_jwks = child_crypto.get_jwks()
    child_keys = child_jwks["keys"]

    # 3. Add child's keys via KeyManager (simulate NodeAttach)
    await key_manager.add_keys(
        keys=child_keys,
        physical_path="/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1",
        system_id="OHGjVrpDX1EnhT1",
        origin=DeliveryOriginType.LOCAL,  # Simplified for test
    )

    # 4. Create a signed envelope from the child
    child_signer = EdDSAEnvelopeSigner(crypto=child_crypto)

    follow_up_frame = AddressBindFrame(
        address="math@/",
        encryption_key_id=child_keys[1]["kid"] if len(child_keys) > 1 else None,
        physical_path="/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1",
    )

    follow_up_envelope = FameEnvelope(frame=follow_up_frame)

    # Set the sid before signing (required by EdDSAEnvelopeSigner)
    follow_up_envelope.sid = secure_digest("/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1")

    # Sign the envelope
    signed_follow_up = child_signer.sign_envelope(
        follow_up_envelope, physical_path="/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1"
    )

    # 5. Try to verify the signed envelope using EnvelopeVerifier directly
    # This is the core test: can EnvelopeVerifier access keys added via KeyManager?
    try:
        await envelope_verifier.verify_envelope(signed_follow_up, check_payload=False)

        # If we get here without exception, the integration works
        print("✅ Full NodeAttach -> Envelope Verification flow succeeded")

    except ValueError as e:
        if "Unknown key id" in str(e):
            pytest.fail(
                f"INTEGRATION BUG: {e}. Keys from NodeAttach not available for envelope verification."
            )
        else:
            raise

    # 6. Verify the key is accessible both ways
    signing_key_id = child_keys[0]["kid"]  # First key is typically signing key

    # Via KeyManager
    assert await key_manager.has_key(signing_key_id), "KeyManager should have the key"

    # Via global key store (what EnvelopeVerifier uses)
    try:
        await global_key_store.get_key(signing_key_id)
        print("✅ Key accessible via both KeyManager and global key store")
    except ValueError:
        pytest.fail("BUG: Key not accessible via global key store")


@pytest.mark.asyncio
async def test_key_manager_factory_creates_consistent_instances():
    """
    Test that KeyManager instances created by factory use the same key store
    as other components.
    """
    print("Testing KeyManager factory consistency...")

    from naylence.fame.security.keys.default_key_manager_factory import (
        DefaultKeyManagerFactory,
    )

    # 1. Create KeyManager via factory (how it's done in production)
    factory = DefaultKeyManagerFactory()
    key_manager_from_factory = await factory.create()

    # 2. Create KeyManager directly with global key store
    global_key_store = get_key_store()
    key_manager_direct = DefaultKeyManager(key_store=global_key_store)

    # 3. Add a key via factory-created manager
    test_key = {
        "kid": "test-key-id",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "test-x-value",
        "use": "sig",
        "alg": "EdDSA",
    }

    await key_manager_from_factory.add_keys(
        keys=[test_key],
        physical_path="/test",
        system_id="test-system",
        origin=DeliveryOriginType.LOCAL,
    )

    # 4. Verify the key is available via direct manager
    assert await key_manager_direct.has_key("test-key-id"), (
        "Key added via factory manager should be available via direct manager"
    )

    # 5. Verify EnvelopeVerifier can access the key
    verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())
    try:
        # This accesses the key via get_key_provider() -> get_key_store()
        retrieved_key = await verifier._key_provider.get_key("test-key-id")
        assert retrieved_key is not None
        print("✅ Key added via factory manager is accessible to EnvelopeVerifier")
    except ValueError as e:
        if "Unknown key id" in str(e):
            pytest.fail("BUG: Factory-created KeyManager not using shared key store")
        else:
            raise


if __name__ == "__main__":
    # Run the tests
    asyncio.run(test_node_attach_keys_available_for_envelope_verification())
    asyncio.run(test_full_node_attach_flow_integration())
    asyncio.run(test_key_manager_factory_creates_consistent_instances())
    print("🎉 All integration tests passed!")
