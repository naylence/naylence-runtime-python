#!/usr/bin/env python3
"""Test AdmissionConfig polymorphic behavior."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "naylence-fame-core", "src"))

from naylence.fame.node.admission.admission_client_factory import AdmissionConfig


def test_admission_config_polymorphic():
    """Test that AdmissionConfig polymorphic dispatch works for DirectAdmissionClient."""
    print("Testing AdmissionConfig polymorphic behavior...")

    # This is similar to the config from the error
    config_data = {
        "type": "DirectAdmissionClient",
        "connector_directive": {
            "type": "HttpStatelessConnector",
            "url": "http://localhost:8080/fame/v1/ingress/downstream/test-system",
            "ttl": 0,
            "durable": False,
        },
        "supported_inbound_connectors": [
            {
                "type": "HttpStatelessConnector",
                "url": "http://localhost:8080/fame/v1/ingress/upstream",
                "ttl": 0,
                "durable": False,
            }
        ],
        "ttl_sec": 600,
        "token_provider": {"type": "SharedSecretTokenProvider", "secret": "changeme"},
    }

    try:
        # Test model_validate polymorphic dispatch
        result = AdmissionConfig.model_validate(config_data)
        print(f"✓ Created: {type(result)}")

        # Check if it's the right type
        from naylence.fame.node.admission.direct_admission_client import (
            DirectNodeAdmissionConfig,
        )

        if isinstance(result, DirectNodeAdmissionConfig):
            print("✓ Polymorphic dispatch worked - created DirectNodeAdmissionConfig")

            # Check if the token_provider field is accessible
            if hasattr(result, "token_provider"):
                print(f"✓ token_provider field exists: {result.token_provider}")
                return True
            else:
                print("✗ token_provider field missing")
                return False
        else:
            print(f"✗ Wrong type created: {type(result)}")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_direct_instantiation():
    """Test direct instantiation of AdmissionConfig."""
    print("\n" + "=" * 50)
    print("Testing direct AdmissionConfig instantiation...")

    try:
        from naylence.fame.node.admission.direct_admission_client import (
            DirectNodeAdmissionConfig,
        )

        # Direct instantiation should also work
        config = AdmissionConfig(
            type="DirectAdmissionClient",
            connector_directive={
                "type": "HttpStatelessConnector",
                "url": "http://test.com/outbox",
            },
            token_provider={"type": "SharedSecretTokenProvider", "secret": "test"},
        )

        print(f"✓ Created: {type(config)}")

        if isinstance(config, DirectNodeAdmissionConfig):
            print("✓ Direct instantiation worked - created DirectNodeAdmissionConfig")
            if hasattr(config, "token_provider"):
                print(f"✓ token_provider field exists: {config.token_provider}")
                return True
            else:
                print("✗ token_provider field missing")
                return False
        else:
            print(f"✗ Wrong type created: {type(config)}")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("Testing AdmissionConfig Polymorphic Behavior")
    print("=" * 60)

    test1 = test_admission_config_polymorphic()
    test2 = test_direct_instantiation()

    print("\n" + "=" * 60)
    print("SUMMARY:")
    print(f"Polymorphic model_validate: {'✓' if test1 else '✗'}")
    print(f"Direct instantiation: {'✓' if test2 else '✗'}")

    if test1 and test2:
        print("\n🎉 AdmissionConfig polymorphic behavior works correctly!")
        print("   This should fix the 'token_provider' attribute error.")
        sys.exit(0)
    else:
        print("\n❌ AdmissionConfig polymorphic behavior still broken.")
        sys.exit(1)
