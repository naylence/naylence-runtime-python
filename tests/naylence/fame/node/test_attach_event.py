"""
Test to verify the on_node_attach_to_upstream event dispatch works correctly.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.security_manager_factory import SecurityManagerFactory


class MockEventListener(NodeEventListener):
    """Mock event listener to track attach events."""

    def __init__(self):
        self.on_node_started_called = False
        self.on_node_attach_to_upstream_called = False
        self.attach_info_received = None

    async def on_node_started(self, node):
        self.on_node_started_called = True

    async def on_node_attach_to_upstream(self, node, attach_info):
        self.on_node_attach_to_upstream_called = True
        self.attach_info_received = attach_info


@pytest.mark.asyncio
async def test_attach_event_with_parent_keys():
    """Test that parent key management works in the attach event."""

    # Create a mock key manager
    mock_key_manager = AsyncMock()

    # Create SecurityManager with mock key manager
    node_security = await SecurityManagerFactory.create_security_manager(
        policy=None,  # Will use default policy
        envelope_signer=None,
        envelope_verifier=None,
        encryption_manager=None,
        key_manager=mock_key_manager,
        authorizer=None,
        certificate_manager=None,
    )

    # Create a mock node
    node = MagicMock()
    node.id = "test-node"
    node.sid = "test-sid"
    node._key_management_handler = None

    # Mock attach info with parent keys
    parent_keys = [{"kid": "parent-key-1", "kty": "OKP"}, {"kid": "parent-key-2", "kty": "RSA"}]
    attach_info = {
        "target_system_id": "parent-node",
        "target_physical_path": "/parent",
        "parent_keys": parent_keys,
    }

    # Call the attach event
    await node_security.on_node_attach_to_upstream(node, attach_info)

    # Verify that the key manager's add_keys method was called with the right parameters
    mock_key_manager.add_keys.assert_called_once()
    call_args = mock_key_manager.add_keys.call_args

    assert call_args[1]["keys"] == parent_keys
    assert call_args[1]["physical_path"] == "/parent"
    assert call_args[1]["system_id"] == "parent-node"


@pytest.mark.asyncio
async def test_attach_event_no_parent_keys():
    """Test that attach event handles missing parent keys gracefully."""

    # Create SecurityManager with default policy
    node_security = await SecurityManagerFactory.create_security_manager(
        policy=None,  # Will use default policy
        envelope_signer=None,
        envelope_verifier=None,
        encryption_manager=None,
        key_manager=None,  # No key manager
        authorizer=None,
        certificate_manager=None,
    )

    # Create a mock node
    node = MagicMock()
    node.id = "test-node"
    node.sid = "test-sid"
    node._key_management_handler = None

    # Mock attach info without parent keys
    attach_info = {
        "target_system_id": "parent-node",
        "target_physical_path": "/parent",
        # No parent_keys field
    }

    # Call the attach event - should not raise an exception
    await node_security.on_node_attach_to_upstream(node, attach_info)

    # Test passes if no exception is raised
    assert True
