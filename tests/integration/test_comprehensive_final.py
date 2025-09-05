from naylence.fame.core.protocol.frames import NodeAttachFrame
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH


def test_reverse_connection_feature():
    """Test the complete reverse connection feature implementation."""
    print("Testing reverse connection feature...")

    # Create connector directives for reverse connections
    websocket_connector = {
        "type": "WebSocketConnectionGrant",
        "purpose": GRANT_PURPOSE_NODE_ATTACH,
        "url": "ws://callback.example.com:8080/ws",
    }

    http_connector = {
        "type": "HttpConnectionGrant",
        "purpose": GRANT_PURPOSE_NODE_ATTACH,
        "url": "http://callback.example.com:8081/outbox",
    }

    print(f"✓ WebSocket connector: {type(websocket_connector)}")
    print(f"✓ HTTP connector: {type(http_connector)}")

    # Create NodeAttachFrame with reverse connection support
    frame = NodeAttachFrame(
        system_id="test-system-123",
        instance_id="test-instance-456",
        child_id="test-child-123",
        physical_path="/test/path",
        metadata={"test": "metadata"},
        callback_grants=[websocket_connector, http_connector],
    )

    print(f"✓ NodeAttachFrame created with {len(frame.callback_grants)} connectors")

    # Test serialization of the complete frame
    try:
        serialized = frame.model_dump()
        print("✓ Frame serialization successful:")
        print(f"  System ID: {serialized['system_id']}")
        print(f"  Instance ID: {serialized['instance_id']}")
        print(f"  Connectors: {len(serialized['callback_grants'])}")

        for i, conn in enumerate(serialized["callback_grants"]):
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
        "callback_grants": [
            {
                "type": "WebSocketConnectionGrant",
                "purpose": GRANT_PURPOSE_NODE_ATTACH,
                "url": "ws://ws.example.com:9090/ws",
            },
            {
                "type": "HttpConnectionGrant",
                "purpose": GRANT_PURPOSE_NODE_ATTACH,
                "url": "http://http.example.com:9091/outbox",
            },
        ],
    }

    try:
        frame = NodeAttachFrame.model_validate(frame_data)
        print("✓ Frame deserialized successfully")
        print(f"  System ID: {frame.system_id}")
        print(f"  Instance ID: {frame.instance_id}")
        print(f"  Connectors: {len(frame.callback_grants)}")

        for i, conn in enumerate(frame.callback_grants):
            print(f"    Connector {i + 1}: {type(conn)} - {conn.type}")

        # Verify polymorphic types
        from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
        from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant

        ws_conn = frame.callback_grants[0]
        http_conn = frame.callback_grants[1]

        if isinstance(ws_conn, WebSocketConnectionGrant) and isinstance(http_conn, HttpConnectionGrant):
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
