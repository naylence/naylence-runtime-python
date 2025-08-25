#!/usr/bin/env python3
"""
Test script to verify the new payload digest functionality.

This test verifies that:
1. DataFrame gets a payload digest (pd field) when signed
2. Intermediate verification works without recomputing payload hash
3. Final destination verification recomputes and verifies the payload hash
4. Non-DataFrame frames continue to use full frame hashing
"""

import pytest

from naylence.fame.core import DataFrame, FameEnvelope, NodeHeartbeatFrame
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier
from naylence.fame.util.util import secure_digest


@pytest.fixture(autouse=True)
async def clean_key_store():
    """Clear global key store before and after each test to ensure isolation."""
    # Clear before test
    key_store = get_key_store()
    key_store._keys.clear()

    # Also reset the global singleton to ensure clean state
    import naylence.fame.security.keys.key_store as ks_module

    ks_module._instance = None

    yield

    # Clear after test
    key_store = get_key_store()
    key_store._keys.clear()

    # Reset singleton again
    ks_module._instance = None


@pytest.mark.asyncio
async def test_payload_digest_verification():
    """Test the new payload digest verification functionality."""
    print("🧪 Testing payload digest verification functionality...")

    # Setup crypto provider and keys
    provider = DefaultCryptoProvider()
    key_store = get_key_store()
    key_provider = get_key_provider()
    jwk = provider.get_jwks()["keys"][0]
    physical_path = "/test_node"
    sid = secure_digest(physical_path)
    jwk["sid"] = sid
    await key_store.add_key(jwk["kid"], jwk)

    signer = EdDSAEnvelopeSigner(crypto=provider)
    verifier = EdDSAEnvelopeVerifier(key_provider=key_provider)

    # Test 1: DataFrame with payload digest
    print("\n1️⃣ Testing DataFrame payload digest...")

    data_frame = DataFrame(payload={"message": "test payload", "data": [1, 2, 3]}, codec="json")
    data_envelope = FameEnvelope(frame=data_frame, sid=sid)

    # Sign the envelope (should populate pd field)
    signer.sign_envelope(data_envelope, physical_path=physical_path)

    assert isinstance(data_envelope.frame, DataFrame), "Frame should be a DataFrame"
    print(f"   ✅ DataFrame.pd field populated: {data_envelope.frame.pd}")
    assert data_envelope.frame.pd is not None, "DataFrame.pd field should be populated"
    assert data_envelope.sec and data_envelope.sec.sig, "Envelope should be signed"

    # Verify as intermediate (check_payload=False)
    try:
        result = await verifier.verify_envelope(data_envelope, check_payload=False)
        print("   ✅ Intermediate verification successful (no payload recomputation)")
        assert result is True
    except Exception as e:
        print(f"   ❌ Intermediate verification failed: {e}")
        raise

    # Verify as final destination (check_payload=True)
    try:
        result = await verifier.verify_envelope(data_envelope, check_payload=True)
        print("   ✅ Final destination verification successful (payload recomputed and verified)")
        assert result is True
    except Exception as e:
        print(f"   ❌ Final destination verification failed: {e}")
        raise

    # Test 2: Non-DataFrame (should use full frame hashing)
    print("\n2️⃣ Testing non-DataFrame frame...")

    heartbeat_frame = NodeHeartbeatFrame(system_id="test_system")
    heartbeat_envelope = FameEnvelope(frame=heartbeat_frame, sid=sid)

    # Sign the envelope
    signer.sign_envelope(heartbeat_envelope, physical_path=physical_path)

    print("   ✅ Non-DataFrame signed successfully")
    assert heartbeat_envelope.sec and heartbeat_envelope.sec.sig, "Envelope should be signed"

    # Verify (both intermediate and final should work the same)
    try:
        result1 = await verifier.verify_envelope(heartbeat_envelope, check_payload=False)
        result2 = await verifier.verify_envelope(heartbeat_envelope, check_payload=True)
        print("   ✅ Non-DataFrame verification successful (both intermediate and final)")
        assert result1 is True and result2 is True
    except Exception as e:
        print(f"   ❌ Non-DataFrame verification failed: {e}")
        raise

    # Test 3: Tampered payload detection
    print("\n3️⃣ Testing tampered payload detection...")

    tampered_frame = DataFrame(payload={"message": "original payload"}, codec="json")
    tampered_envelope = FameEnvelope(frame=tampered_frame, sid=sid)

    # Sign the envelope
    signer.sign_envelope(tampered_envelope, physical_path=physical_path)

    # Tamper with the payload
    assert isinstance(tampered_envelope.frame, DataFrame), "Frame should be a DataFrame"
    tampered_envelope.frame.payload = {"message": "tampered payload"}

    # Intermediate verification should still pass (doesn't check payload)
    try:
        result = await verifier.verify_envelope(tampered_envelope, check_payload=False)
        print("   ✅ Intermediate verification passed for tampered payload (expected)")
        assert result is True
    except Exception as e:
        print(f"   ❌ Unexpected intermediate verification failure: {e}")
        raise

    # Final destination verification should fail
    try:
        await verifier.verify_envelope(tampered_envelope, check_payload=True)
        print("   ❌ Final destination verification should have failed for tampered payload")
        assert False, "Verification should have failed for tampered payload"
    except ValueError as e:
        if "Payload digest mismatch" in str(e):
            print("   ✅ Final destination correctly detected tampered payload")
        else:
            print(f"   ❌ Unexpected error for tampered payload: {e}")
            raise

    print("\n🎉 All tests passed! Payload digest verification is working correctly.")
    print("\n📋 Summary:")
    print("   • DataFrame payloads are hashed once at origin and verified at destination")
    print("   • Intermediate nodes verify signatures without recomputing payload hashes")
    print("   • Non-DataFrame frames continue to use full frame hashing")
    print("   • Payload tampering is correctly detected at final destination")
