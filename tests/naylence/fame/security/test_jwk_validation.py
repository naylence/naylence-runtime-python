#!/usr/bin/env python3
"""
Test script to verify JWK validation and use field enforcement.
"""

import pytest

from naylence.fame.security.crypto.jwk_validation import (
    JWKValidationError,
    filter_keys_by_use,
    validate_encryption_key,
    validate_jwk_complete,
    validate_signing_key,
)
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.keys.key_store import get_key_store


def create_test_keys():
    """Create various test keys for validation."""

    # Valid signing key (Ed25519)
    valid_signing_key = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "abcdefghijklmnopqrstuvwxyz123456",
        "kid": "test-signing-key",
        "use": "sig",
        "alg": "EdDSA",
    }

    # Valid encryption key (X25519)
    valid_encryption_key = {
        "kty": "OKP",
        "crv": "X25519",
        "x": "abcdefghijklmnopqrstuvwxyz123456",
        "kid": "test-encryption-key",
        "use": "enc",
        "alg": "ECDH-ES",
    }

    # Invalid key - missing use field
    invalid_no_use = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "abcdefghijklmnopqrstuvwxyz123456",
        "kid": "test-no-use-key",
        "alg": "EdDSA",
    }

    # Invalid key - wrong use field
    invalid_bad_use = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "abcdefghijklmnopqrstuvwxyz123456",
        "kid": "test-bad-use-key",
        "use": "invalid",
        "alg": "EdDSA",
    }

    # Invalid key - missing required fields
    invalid_missing_fields = {"kty": "OKP", "kid": "test-missing-fields", "use": "sig"}

    # Wrong key type for encryption
    wrong_type_for_encryption = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "abcdefghijklmnopqrstuvwxyz123456",
        "kid": "test-wrong-type-enc",
        "use": "enc",  # Ed25519 marked for encryption (should be signing)
        "alg": "EdDSA",
    }

    return {
        "valid_signing": valid_signing_key,
        "valid_encryption": valid_encryption_key,
        "invalid_no_use": invalid_no_use,
        "invalid_bad_use": invalid_bad_use,
        "invalid_missing_fields": invalid_missing_fields,
        "wrong_type_for_encryption": wrong_type_for_encryption,
    }


def test_jwk_validation():
    """Test basic JWK validation."""
    print("=== Testing JWK Validation ===")

    test_keys = create_test_keys()

    # Test valid keys
    try:
        use = validate_jwk_complete(test_keys["valid_signing"])
        assert use == "sig"
        print("✅ Valid signing key validation passed")
    except Exception as e:
        print(f"❌ Valid signing key validation failed: {e}")

    try:
        use = validate_jwk_complete(test_keys["valid_encryption"])
        assert use == "enc"
        print("✅ Valid encryption key validation passed")
    except Exception as e:
        print(f"❌ Valid encryption key validation failed: {e}")

    # Test invalid keys
    try:
        validate_jwk_complete(test_keys["invalid_no_use"])
        print("❌ Should have rejected key without use field")
    except JWKValidationError:
        print("✅ Correctly rejected key without use field")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    try:
        validate_jwk_complete(test_keys["invalid_bad_use"])
        print("❌ Should have rejected key with invalid use field")
    except JWKValidationError:
        print("✅ Correctly rejected key with invalid use field")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    try:
        validate_jwk_complete(test_keys["invalid_missing_fields"])
        print("❌ Should have rejected key with missing fields")
    except JWKValidationError:
        print("✅ Correctly rejected key with missing fields")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def test_specific_key_validation():
    """Test encryption and signing specific validation."""
    print("\n=== Testing Specific Key Type Validation ===")

    test_keys = create_test_keys()

    # Test encryption key validation
    try:
        validate_encryption_key(test_keys["valid_encryption"])
        print("✅ Valid encryption key specific validation passed")
    except Exception as e:
        print(f"❌ Valid encryption key specific validation failed: {e}")

    try:
        validate_encryption_key(test_keys["valid_signing"])
        print("❌ Should have rejected signing key for encryption")
    except JWKValidationError:
        print("✅ Correctly rejected signing key for encryption")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    try:
        validate_encryption_key(test_keys["wrong_type_for_encryption"])
        print("❌ Should have rejected Ed25519 key marked for encryption")
    except JWKValidationError:
        print("✅ Correctly rejected Ed25519 key marked for encryption")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    # Test signing key validation
    try:
        validate_signing_key(test_keys["valid_signing"])
        print("✅ Valid signing key specific validation passed")
    except Exception as e:
        print(f"❌ Valid signing key specific validation failed: {e}")

    try:
        validate_signing_key(test_keys["valid_encryption"])
        print("❌ Should have rejected encryption key for signing")
    except JWKValidationError:
        print("✅ Correctly rejected encryption key for signing")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


def test_key_filtering():
    """Test filtering keys by use."""
    print("\n=== Testing Key Filtering ===")

    test_keys = create_test_keys()
    all_keys = list(test_keys.values())

    # Filter for signing keys
    signing_keys = filter_keys_by_use(all_keys, "sig")
    print(f"Found {len(signing_keys)} signing keys")

    expected_signing = ["test-signing-key"]  # Only the valid signing key should be found
    actual_signing = [k["kid"] for k in signing_keys]

    if set(actual_signing) == set(expected_signing):
        print("✅ Signing key filtering worked correctly")
    else:
        print(f"❌ Signing key filtering failed. Expected: {expected_signing}, Got: {actual_signing}")

    # Filter for encryption keys
    encryption_keys = filter_keys_by_use(all_keys, "enc")
    print(f"Found {len(encryption_keys)} encryption keys")

    expected_encryption = ["test-encryption-key"]  # Only the valid encryption key should be found
    actual_encryption = [k["kid"] for k in encryption_keys]

    if set(actual_encryption) == set(expected_encryption):
        print("✅ Encryption key filtering worked correctly")
    else:
        print(
            f"❌ Encryption key filtering failed. Expected: {expected_encryption}, Got: {actual_encryption}"
        )


@pytest.mark.asyncio
async def test_key_store_validation():
    """Test that key store validates keys on addition."""
    print("\n=== Testing Key Store Validation ===")

    key_store = get_key_store()
    test_keys = create_test_keys()

    # Clear any existing keys
    if hasattr(key_store, "_keys"):
        key_store._keys.clear()  # type: ignore

    # Test adding valid keys
    all_test_keys = list(test_keys.values())
    await key_store.add_keys(all_test_keys, physical_path="/test")

    # Check which keys were actually added
    stored_keys = list(await key_store.get_keys())
    stored_kids = [k["kid"] for k in stored_keys]

    expected_valid_kids = ["test-signing-key", "test-encryption-key"]

    valid_stored = [kid for kid in stored_kids if kid in expected_valid_kids]

    print(f"Stored {len(stored_keys)} keys total")
    print(f"Valid keys stored: {valid_stored}")

    if set(valid_stored) == set(expected_valid_kids):
        print("✅ Key store correctly accepted only valid keys")
    else:
        print(f"❌ Key store validation failed. Expected: {expected_valid_kids}, Got valid: {valid_stored}")


@pytest.mark.asyncio
async def test_real_crypto_provider_keys():
    """Test validation of real keys from the crypto provider."""
    print("\n=== Testing Real Crypto Provider Keys ===")

    try:
        crypto_provider = get_crypto_provider()
        jwks = crypto_provider.get_jwks()

        print(f"Got {len(jwks['keys'])} keys from crypto provider")

        all_valid = True
        for i, key in enumerate(jwks["keys"]):
            try:
                use = validate_jwk_complete(key)
                kid = key.get("kid", f"key-{i}")
                print(f"✅ Key {kid}: {use} - valid")
            except JWKValidationError as e:
                kid = key.get("kid", f"key-{i}")
                print(f"❌ Key {kid}: validation failed - {e}")
                all_valid = False

        if all_valid:
            print("✅ All crypto provider keys are valid")
        else:
            print("❌ Some crypto provider keys are invalid")

    except Exception as e:
        print(f"❌ Failed to test crypto provider keys: {e}")


@pytest.mark.asyncio
async def test_main_jwk_validation():
    """Run all tests."""
    print("🧪 Testing JWK validation and use field enforcement\n")

    test_jwk_validation()
    test_specific_key_validation()
    test_key_filtering()
    await test_key_store_validation()
    await test_real_crypto_provider_keys()

    print("\n✅ JWK validation testing complete!")
