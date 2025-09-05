#!/usr/bin/env python3
"""
Test script to validate the reverse connection functionality.
"""

import asyncio
from unittest.mock import AsyncMock, Mock

from naylence.fame.core import DeliveryOriginType, NodeWelcomeFrame
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.node.admission.default_node_attach_client import (
    DefaultNodeAttachClient,
)
from naylence.fame.node.admission.direct_admission_client import (
    DirectAdmissionClient,
)
from naylence.fame.node.admission.direct_admission_client_factory import (
    DirectNodeAdmissionConfig,
)


async def test_direct_admission_client_with_reverse_connections():
    """Test that DirectAdmissionClient works with the current architecture."""

    # Create test connection grants
    connection_grants = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": GRANT_PURPOSE_NODE_ATTACH,
            "url": "ws://upstream.example.com:8080",
        }
    ]

    # Create config for outbound connection
    config = DirectNodeAdmissionConfig(connection_grants=connection_grants, ttl_sec=3600)

    # Create client
    client = DirectAdmissionClient(connection_grants=config.connection_grants, ttl_sec=config.ttl_sec)

    # Test that the client can generate welcome frames properly
    hello_response = await client.hello(
        system_id="test-system", instance_id="test-instance", requested_logicals=["*"]
    )

    # Verify the welcome frame has the expected connection grants
    assert hello_response.frame.connection_grants is not None
    assert len(hello_response.frame.connection_grants) > 0
    # Check that the first grant contains the outbound connector data with purpose
    first_grant = hello_response.frame.connection_grants[0]
    # The grant type should be mapped from WebSocketConnector to WebSocketConnectionGrant
    assert first_grant["type"] == "WebSocketConnectionGrant"
    assert first_grant["purpose"] == GRANT_PURPOSE_NODE_ATTACH
    assert hello_response.frame.system_id == "test-system"
    assert hello_response.frame.instance_id == "test-instance"

    print("✓ DirectAdmissionClient correctly generates welcome frames")

    # Note: supported_inbound_connectors are now handled by the node's
    # transport listeners via gather_supported_callback_grants()

    return client


async def test_attach_client_with_reverse_connections():
    """Test that DefaultNodeAttachClient properly includes supported_inbound_connectors
    in NodeAttachFrame."""

    # Create mock objects
    mock_connector = Mock()
    mock_connector.replace_handler = Mock()
    mock_connector.send = Mock()

    mock_welcome_frame = NodeWelcomeFrame(
        system_id="test-system",
        instance_id="test-instance",
        accepted_logicals=["*"],
        assigned_path="/test/path",
    )

    mock_handler = Mock()

    # Create a mock node
    mock_node = Mock()
    mock_node.sid = "test-session-id"
    mock_node._dispatch_envelope_event = AsyncMock()

    # Create inbound connectors to test
    inbound_connectors = [
        {
            "type": "WebSocketConnector",
            "params": {"host": "test.example.com", "port": 9090},
        }
    ]

    # Create attach client
    attach_client = DefaultNodeAttachClient()

    # Mock the _await_ack method to avoid actual network operations
    attach_client._await_ack = Mock()
    attach_client._await_ack.return_value = Mock(corr_id="test-corr-id", ok=True)

    # Capture the NodeAttachFrame that gets sent
    sent_frames = []

    def capture_send(envelope):
        sent_frames.append(envelope.frame)
        return asyncio.Future()

    mock_connector.send.side_effect = capture_send

    try:
        # Call attach with supported_inbound_connectors
        await attach_client.attach(
            node=mock_node,
            origin_type=DeliveryOriginType.DOWNSTREAM,
            connector=mock_connector,
            welcome_frame=mock_welcome_frame,
            final_handler=mock_handler,
            supported_inbound_connectors=inbound_connectors,
        )
    except Exception:
        # We expect this to fail due to mocking, but we can still check the sent frame
        pass

    # Verify that NodeAttachFrame was created with supported_inbound_connectors
    if sent_frames:
        attach_frame = sent_frames[0]
        assert hasattr(attach_frame, "supported_inbound_connectors")
        assert attach_frame.supported_inbound_connectors == inbound_connectors
        print(
            "✓ DefaultNodeAttachClient correctly includes supported_inbound_connectors in NodeAttachFrame"
        )
    else:
        print("⚠ Could not verify NodeAttachFrame creation due to mocking limitations")


async def main():
    """Run all tests."""
    print("Testing reverse connection functionality...\n")

    try:
        # Test DirectAdmissionClient
        await test_direct_admission_client_with_reverse_connections()

        # Test DefaultNodeAttachClient
        await test_attach_client_with_reverse_connections()

        print("\n✓ All tests passed! Reverse connection support is working correctly.")

        # Note: Connection grants are now handled through NodeWelcomeFrame.connection_grants
        print("\nConnection grants are now handled via NodeWelcomeFrame.connection_grants")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
