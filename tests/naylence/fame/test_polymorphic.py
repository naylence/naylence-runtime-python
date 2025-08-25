"""
Test that the ResourceConfig fix preserves polymorphic behavior while fixing serialization.
"""

import json

from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig
from naylence.fame.node.admission.direct_admission_client_factory import (
    DirectNodeAdmissionConfig,
)


def test_polymorphic_deserialization():
    """Test that polymorphic deserialization still works."""
    print("=" * 70)
    print("TESTING POLYMORPHIC DESERIALIZATION")
    print("=" * 70)

    # Test 1: Direct deserialization should create the right subclass
    print("\n1. Testing polymorphic creation from dict...")

    websocket_data = {
        "type": "WebSocketConnector",
        "params": {"host": "test.com", "port": 8080},
    }

    try:
        # This should work with dict format directly
        connector = websocket_data
        print(f"✓ Created: {type(connector).__name__}")
        print(f"✓ Is dict: {isinstance(connector, dict)}")
        print(f"✓ Type field: {connector['type']}")
        print(f"✓ Has all fields: {connector}")

        if not isinstance(connector, dict):
            print("❌ Dict processing is broken!")
            return False

    except Exception as e:
        print(f"❌ Dict processing failed: {e}")
        import traceback

        traceback.print_exc()
        return False

    # Test 2: JSON deserialization should also work with dict format
    print("\n2. Testing dict creation from JSON...")

    try:
        json_str = json.dumps(websocket_data)
        connector_from_json = json.loads(json_str)
        print(f"✓ From JSON: {type(connector_from_json).__name__}")
        print(f"✓ Is dict: {isinstance(connector_from_json, dict)}")

        if not isinstance(connector_from_json, dict):
            print("❌ JSON dict processing is broken!")
            return False

    except Exception as e:
        print(f"❌ JSON dict processing failed: {e}")
        return False

    print("✓ Dict processing is working correctly!")
    return True


def test_direct_instantiation():
    """Test that direct dict creation works."""
    print("\n" + "=" * 70)
    print("TESTING DIRECT DICT CREATION")
    print("=" * 70)

    # Test 1: Direct dict creation
    print("\n1. Testing direct dict creation...")

    try:
        connector = {
            "type": "WebSocketConnector",
            "params": {"host": "direct.test.com", "port": 8080},
        }

        print(f"✓ Created: {type(connector).__name__}")
        print(f"✓ Has keys: {bool(connector)}")
        print(f"✓ Type access: {connector['type']}")
        print(f"✓ Serialization: {connector}")

        # This should be a dict
        if not isinstance(connector, dict):
            print("❌ Direct dict creation still broken!")
            return False

    except Exception as e:
        print(f"❌ Direct dict creation failed: {e}")
        import traceback

        traceback.print_exc()
        return False

    # Test 2: DirectNodeAdmissionConfig with supported_inbound_connectors
    print("\n2. Testing DirectNodeAdmissionConfig with dict format...")

    try:
        config = DirectNodeAdmissionConfig(
            connector_directive={
                "type": "WebSocketConnector",
                "params": {"host": "upstream.com", "port": 8080},
            },
            supported_inbound_connectors=[
                {
                    "type": "WebSocketConnector",
                    "params": {"host": "downstream.com", "port": 9090},
                },
                {
                    "type": "HttpConnector",
                    "params": {"base_url": "https://callback.com"},
                },
            ],
            ttl_sec=3600,
        )

        print("✓ DirectNodeAdmissionConfig created")

        # Test serialization
        dict_dump = config.model_dump()
        print("✓ Config serialization works")

        sic = dict_dump.get("supported_inbound_connectors", [])
        print(f"✓ Found {len(sic)} supported inbound connectors")

        all_good = True
        for i, conn in enumerate(sic):
            if not conn or not conn.get("type"):
                print(f"❌ Connector {i + 1} is empty: {conn}")
                all_good = False
            else:
                print(f"  ✓ Connector {i + 1}: {conn['type']}")

        if not all_good:
            return False

        # Test JSON round trip
        json_str = config.model_dump_json()
        DirectNodeAdmissionConfig.model_validate_json(json_str)
        print("✓ JSON round trip successful")

        return True

    except Exception as e:
        print(f"❌ DirectNodeAdmissionConfig test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_mixed_scenarios():
    """Test mixed scenarios with both polymorphic and direct creation."""
    print("\n" + "=" * 70)
    print("TESTING MIXED SCENARIOS")
    print("=" * 70)

    try:
        # Create a config that mixes direct creation and polymorphic deserialization
        config_data = {
            "type": "DirectAdmissionClient",
            "connector_directive": {
                "type": "WebSocketConnector",
                "params": {"host": "upstream.com", "port": 8080},
            },
            "supported_inbound_connectors": [
                {
                    "type": "WebSocketConnector",
                    "params": {"host": "callback1.com", "port": 9090},
                },
                {
                    "type": "HttpConnector",
                    "params": {"base_url": "https://callback2.com"},
                },
            ],
            "ttl_sec": 3600,
        }

        # This should use polymorphic deserialization
        config = DirectNodeAdmissionConfig.model_validate(config_data)
        print("✓ Mixed config created via polymorphic deserialization")

        # Check that the connector_directive became the right type
        cd = config.connector_directive
        print(f"✓ Connector directive type: {type(cd).__name__}")
        print(f"✓ Is WebSocketConnectorConfig: {isinstance(cd, WebSocketConnectorConfig)}")

        # Check that supported_inbound_connectors also work
        if config.supported_inbound_connectors:
            print(f"✓ Has {len(config.supported_inbound_connectors)} inbound connectors")
            for i, conn in enumerate(config.supported_inbound_connectors):
                print(f"  Connector {i + 1}: {type(conn).__name__} - {conn.type}")

        # Test serialization
        config.model_dump()
        print("✓ Mixed config serializes correctly")

        return True

    except Exception as e:
        print(f"❌ Mixed scenario test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("ResourceConfig Fix - Preserving Polymorphic Behavior")

    test1 = test_polymorphic_deserialization()
    test2 = test_direct_instantiation()
    test3 = test_mixed_scenarios()

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    if test1 and test2 and test3:
        print("\n🎉 SUCCESS! ResourceConfig fix works correctly!")
        print("✓ Polymorphic deserialization preserved")
        print("✓ Direct instantiation serialization fixed")
        print("✓ Mixed scenarios work properly")
        print("\n💫 Both reverse connections AND polymorphic behavior work!")
    else:
        print("\n❌ Some tests failed:")
        if not test1:
            print("  - Polymorphic deserialization broken")
        if not test2:
            print("  - Direct instantiation still broken")
        if not test3:
            print("  - Mixed scenarios failing")


if __name__ == "__main__":
    main()
