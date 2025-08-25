#!/usr/bin/env python3
"""
Test script to verify dual-key (signing + encryption) certificate integration.
"""

from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider


def test_dual_key_integration():
    """Test that crypto provider correctly handles both signing and encryption keys with certificates."""

    print("Testing dual-key certificate integration...")

    # Get crypto provider instance
    provider = get_crypto_provider()

    # Test 1: Check regular JWKS (should have 2 keys: signing + encryption)
    jwks = provider.get_jwks()
    print(f"\nRegular JWKS: {len(jwks['keys'])} keys")
    for i, key in enumerate(jwks["keys"]):
        print(f"  Key {i + 1}: kty={key.get('kty')}, use={key.get('use')}, kid={key.get('kid')}")

    # Test 2: Check certificate-enabled signing JWK
    node_jwk = provider.node_jwk()
    print("\nCertificate-enabled JWK:")
    print(f"  kty={node_jwk.get('kty')}, use={node_jwk.get('use')}, kid={node_jwk.get('kid')}")
    print(f"  Has certificate: {'x5c' in node_jwk}")

    # Test 3: Simulate the _get_keys() logic
    keys = []

    # Add certificate-enabled signing key
    if node_jwk:
        keys.append(node_jwk)

    # Add all other keys (encryption + fallback signing)
    if jwks and jwks.get("keys"):
        for jwk in jwks["keys"]:
            # Skip regular signing key if we have certificate-enabled one
            if node_jwk and jwk.get("kid") == node_jwk.get("kid") and jwk.get("use") != "enc":
                continue
            keys.append(jwk)

    print(f"\nFinal key list for node attachment: {len(keys)} keys")
    for i, key in enumerate(keys):
        has_cert = "x5c" in key
        print(
            f"  Key {i + 1}: kty={key.get('kty')}, use={key.get('use')}, "
            f"kid={key.get('kid')}, has_cert={has_cert}"
        )

    # Test 4: Verify we have both signing and encryption
    signing_keys = [k for k in keys if k.get("use") == "sig" or k.get("use") is None]
    encryption_keys = [k for k in keys if k.get("use") == "enc"]

    print("\nKey breakdown:")
    print(f"  Signing keys: {len(signing_keys)}")
    print(f"  Encryption keys: {len(encryption_keys)}")

    # Test 5: Verify certificate integration
    cert_keys = [k for k in keys if "x5c" in k]
    print(f"  Keys with certificates: {len(cert_keys)}")

    # Validate expectations
    assert len(keys) >= 2, "Should have at least 2 keys (signing + encryption)"
    assert len(signing_keys) >= 1, "Should have at least 1 signing key"
    assert len(encryption_keys) >= 1, "Should have at least 1 encryption key"
    assert len(cert_keys) <= 1, "Should have at most 1 certificate (on signing key only)"

    if cert_keys:
        cert_key = cert_keys[0]
        assert cert_key.get("use") in [None, "sig"], "Certificate should only be on signing key"
        print("  ✓ Certificate is correctly attached to signing key")

    print("\n✓ All dual-key integration tests passed!")


if __name__ == "__main__":
    success = test_dual_key_integration()
    exit(0 if success else 1)
