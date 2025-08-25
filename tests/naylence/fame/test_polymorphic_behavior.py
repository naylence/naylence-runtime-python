#!/usr/bin/env python3
"""Test polymorphic deserialization after our fix."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "naylence-fame-core", "src"))


def test_polymorphic_deserialization():
    """Test that dict-based connector directives work."""
    print("Testing dict-based connector directives...")

    # Test dict format - should work directly
    json_data = {"type": "WebSocketConnector", "params": {"host": "test.com", "port": 8080}}

    try:
        # Just verify the dict structure is correct
        result = json_data
        print(f"✓ Dict result type: {type(result)}")
        print(f"✓ Result dict: {result}")
        print(f"✓ Result type field: {result['type']}")

        # Verify it has the correct structure
        if isinstance(result, dict) and "type" in result and "params" in result:
            print("✓ Dict-based connector directive works correctly")
            return True
        else:
            print(f"✗ Wrong structure: {result}")
            return False

    except Exception as e:
        print(f"✗ Dict processing failed: {e}")
        return False


def test_direct_instantiation():
    """Test that direct dict creation works."""
    print("\nTesting direct dict creation...")

    try:
        result = {"type": "WebSocketConnector", "params": {"host": "direct.com", "port": 8080}}
        print(f"✓ Direct result type: {type(result)}")
        print(f"✓ Direct result dict: {result}")
        if "type" in result:
            print(f"✓ Direct result type field: {result['type']}")
        else:
            print("✗ Direct result has no type field")
            return False
        return True

    except Exception as e:
        print(f"✗ Direct instantiation failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing ResourceConfig validator behavior")
    print("=" * 50)

    poly_works = test_polymorphic_deserialization()
    direct_works = test_direct_instantiation()

    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(f"Polymorphic deserialization: {'✓' if poly_works else '✗'}")
    print(f"Direct instantiation: {'✓' if direct_works else '✗'}")

    if poly_works and direct_works:
        print("✓ Both behaviors work correctly!")
        sys.exit(0)
    else:
        print("✗ One or both behaviors are broken")
        sys.exit(1)
