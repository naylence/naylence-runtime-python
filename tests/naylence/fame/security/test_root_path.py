#!/usr/bin/env python3
"""
Test script to verify that root path addresses trigger address-based key requests.
"""

import pytest

# Add the src directory to Python path
from naylence.fame.core.address.address import FameAddress
from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import EncryptionConfig


@pytest.mark.asyncio
async def test_root_path_encryption_key_lookup():
    """Test that root path addresses trigger address-based key requests."""
    print("Testing root path encryption key lookup...")

    # Create a security policy with flexible crypto config
    flexible_config = EncryptionConfig()
    policy = DefaultSecurityPolicy(encryption=flexible_config)

    # Test root path address
    root_address = FameAddress("math@/")
    print(f"Testing address: {root_address}")

    # Create an envelope with the root path destination
    envelope = FameEnvelope(
        id="test-envelope",
        to=root_address,
        frame=DataFrame(payload={"test": "data"}),
    )

    try:
        kid, pub_key_bytes = await policy._lookup_recipient_encryption_key(envelope.to)
        print(f"❌ Expected exception but got: {kid}, {pub_key_bytes}")
        return False

    except ValueError as e:
        expected_msg = f"No encryption key found for address {root_address}"
        if expected_msg in str(e):
            print("✅ Root path address correctly triggers key request")
            return True
        else:
            print(f"❌ Unexpected error message: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected exception type: {e}")
        return False


@pytest.mark.asyncio
async def test_regular_path_encryption_key_lookup():
    """Test that regular path addresses also trigger address-based key requests."""
    print("\nTesting regular path encryption key lookup...")

    # Create a security policy with flexible crypto config
    flexible_config = EncryptionConfig()
    policy = DefaultSecurityPolicy(encryption=flexible_config)

    # Test regular path address
    regular_address = FameAddress("math@/system1/service")
    print(f"Testing address: {regular_address}")

    # Create an envelope with the regular path destination
    envelope = FameEnvelope(
        id="test-envelope",
        to=regular_address,
        frame=DataFrame(payload={"test": "data"}),
    )

    try:
        kid, pub_key_bytes = await policy._lookup_recipient_encryption_key(envelope.to)
        print(f"❌ Expected exception but got: {kid}, {pub_key_bytes}")
        return False
    except ValueError as e:
        expected_msg = f"No encryption key found for address {regular_address}"
        if expected_msg in str(e):
            print("✅ Regular path address correctly triggers key request")
            return True
        else:
            print(f"❌ Unexpected error message: {e}")
            return False
    except Exception as e:
        print(f"❌ Unexpected exception type: {e}")
        return False
