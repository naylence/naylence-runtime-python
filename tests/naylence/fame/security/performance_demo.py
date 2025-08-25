"""
Performance demonstration for payload digest verification.

This script demonstrates the performance benefits of the new signature architecture
where intermediate nodes don't need to recompute large payload hashes.
"""

import time

from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.crypto.providers.default_crypto_provider import (
    DefaultCryptoProvider,
)
from naylence.fame.security.crypto.providers.eddsa_envelope_signer import (
    EdDSAEnvelopeSigner,
)
from naylence.fame.security.crypto.providers.eddsa_envelope_verifier import (
    EdDSAEnvelopeVerifier,
)
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.util.util import secure_digest


def setup_crypto():
    """Setup crypto components."""
    provider = DefaultCryptoProvider()
    key_store = get_key_store()
    key_provider = get_key_provider()

    jwk = provider.get_jwks()["keys"][0]
    physical_path = "/test_node"
    sid = secure_digest(physical_path)
    jwk["sid"] = sid

    key_store.add_key(jwk["kid"], jwk)

    signer = EdDSAEnvelopeSigner(crypto=provider)
    verifier = EdDSAEnvelopeVerifier(key_provider=key_provider)

    return signer, verifier, physical_path, sid


def create_large_payload(size_kb: int) -> dict:
    """Create a large payload for testing."""
    # Create a payload with approximately size_kb kilobytes
    data_size = size_kb * 1024 // 50  # Rough estimate for JSON overhead
    return {
        "data": list(range(data_size)),
        "metadata": {
            "size_kb": size_kb,
            "description": "Large payload for performance testing",
            "timestamp": "2025-06-28T00:00:00Z",
        },
    }


def time_verification(
    verifier: EdDSAEnvelopeVerifier,
    envelope: FameEnvelope,
    check_payload: bool,
    iterations: int = 100,
) -> float:
    """Time verification operations."""
    start_time = time.perf_counter()

    for _ in range(iterations):
        verifier.verify_envelope(envelope, check_payload=check_payload)

    end_time = time.perf_counter()
    return (end_time - start_time) / iterations


def main():
    print("🚀 Payload Digest Performance Demonstration")
    print("=" * 60)

    signer, verifier, physical_path, sid = setup_crypto()

    # Test with different payload sizes
    payload_sizes = [1, 10, 100, 500]  # KB
    iterations = 50

    print(f"Testing with {iterations} iterations per measurement\n")

    for size_kb in payload_sizes:
        print(f"📦 Testing with {size_kb}KB payload:")

        # Create and sign large payload
        payload = create_large_payload(size_kb)
        frame = DataFrame(payload=payload, codec="json")
        envelope = FameEnvelope(frame=frame, sid=sid)
        signed_envelope = signer.sign_envelope(envelope, physical_path=physical_path)

        # Time intermediate verification (check_payload=False)
        intermediate_time = time_verification(
            verifier, signed_envelope, check_payload=False, iterations=iterations
        )

        # Time final destination verification (check_payload=True)
        final_time = time_verification(verifier, signed_envelope, check_payload=True, iterations=iterations)

        # Calculate speedup
        speedup = final_time / intermediate_time if intermediate_time > 0 else float("inf")

        print(f"   🔄 Intermediate verification: {intermediate_time * 1000:.2f}ms")
        print(f"   🎯 Final verification:       {final_time * 1000:.2f}ms")
        print(f"   ⚡ Speedup:                 {speedup:.1f}x faster")
        print()

    print("📊 Summary:")
    print("   • Intermediate nodes verify signatures in constant time")
    print("   • Large payloads don't affect intermediate verification performance")
    print("   • Final destinations pay the cost of payload verification only once")
    print("   • This architecture enables efficient routing of large messages")


if __name__ == "__main__":
    main()
