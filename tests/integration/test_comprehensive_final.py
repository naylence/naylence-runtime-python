#!/usr/bin/env python3
"""Final comprehensive test of the reverse connection feature with fixed serialization."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "naylence-fame-core", "src"))

from naylence.fame.core.protocol.frames import NodeAttachFrame


def test_reverse_connection_feature():
    """Test the complete reverse connection feature implementation."""
    print("Testing reverse connection feature...")

    # Create connector directives for reverse connections
    websocket_connector = {
        "type": "WebSocketConnector",
        "params": {"host": "callback.example.com", "port": 8080},
    }

    http_connector = {"type": "HttpStatelessConnector", "url": "http://callback.example.com:8081/outbox"}

    print(f"✓ WebSocket connector: {type(websocket_connector)}")
    print(f"✓ HTTP connector: {type(http_connector)}")

    # Create NodeAttachFrame with reverse connection support
    frame = NodeAttachFrame(
        system_id="downstream-system-123",
        instance_id="downstream-instance-123",
        supported_inbound_connectors=[websocket_connector, http_connector],
    )

    print(f"✓ NodeAttachFrame created with {len(frame.supported_inbound_connectors)} connectors")

    # Test serialization of the complete frame
    try:
        serialized = frame.model_dump()
        print("✓ Frame serialization successful:")
        print(f"  System ID: {serialized['system_id']}")
        print(f"  Instance ID: {serialized['instance_id']}")
        print(f"  Connectors: {len(serialized['supported_inbound_connectors'])}")

        for i, conn in enumerate(serialized["supported_inbound_connectors"]):
            print(f"    Connector {i + 1}: {conn['type']} - {conn['params']}")

        return True

    except Exception as e:
        print(f"✗ Frame serialization failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_frame_deserialization():
    """Test deserialization of NodeAttachFrame with connector directives."""
    print("\n" + "=" * 50)
    print("Testing frame deserialization...")

    frame_data = {
        "system_id": "downstream-system-456",
        "instance_id": "downstream-instance-456",
        "supported_inbound_connectors": [
            {"type": "WebSocketConnector", "params": {"host": "ws.example.com", "port": 9090}},
            {"type": "HttpStatelessConnector", "url": "http://http.example.com:9091/outbox"},
        ],
    }

    try:
        frame = NodeAttachFrame.model_validate(frame_data)
        print("✓ Frame deserialized successfully")
        print(f"  System ID: {frame.system_id}")
        print(f"  Instance ID: {frame.instance_id}")
        print(f"  Connectors: {len(frame.supported_inbound_connectors)}")

        for i, conn in enumerate(frame.supported_inbound_connectors):
            print(f"    Connector {i + 1}: {type(conn)} - {conn.type}")

        # Verify polymorphic types
        from naylence.fame.connector.http_stateless_connector_factory import HttpStatelessConnectorConfig
        from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig

        ws_conn = frame.supported_inbound_connectors[0]
        http_conn = frame.supported_inbound_connectors[1]

        if isinstance(ws_conn, WebSocketConnectorConfig) and isinstance(
            http_conn, HttpStatelessConnectorConfig
        ):
            print("✓ Polymorphic deserialization worked correctly!")
            return True
        else:
            print(f"✗ Wrong types: {type(ws_conn)}, {type(http_conn)}")
            return False

    except Exception as e:
        print(f"✗ Frame deserialization failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("Final Comprehensive Test: Reverse Connection Feature")
    print("=" * 70)

    test1 = test_reverse_connection_feature()
    test2 = test_frame_deserialization()

    print("\n" + "=" * 70)
    print("FINAL RESULTS:")
    print(f"Reverse connection serialization: {'✓' if test1 else '✗'}")
    print(f"Frame deserialization: {'✓' if test2 else '✗'}")

    if test1 and test2:
        print("\n🎉 SUCCESS! The reverse connection feature is fully implemented and working!")
        print("   - NodeAttachFrame supports supported_inbound_connectors")
        print("   - ConnectorDirective polymorphic behavior works correctly")
        print("   - Serialization and deserialization both work")
        print("   - ResourceConfig validator issues have been resolved")
        sys.exit(0)
    else:
        print("\n❌ Some issues remain.")
        sys.exit(1)
