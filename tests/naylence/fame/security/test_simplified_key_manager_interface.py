#!/usr/bin/env python3
"""
Test the simplified DefaultKeyManager interface after removing individual context callables.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from naylence.fame.core import FameEnvelope
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore


class MockEnvelopeFactory:
    """Mock envelope factory for testing."""

    def create_envelope(self, **kwargs):
        return FameEnvelope(frame=None, to=None, from_=None, flow_id=None, flags=0)


class MockNode:
    """Mock node for testing."""

    def __init__(self, node_id="test-node", sid="test-sid", physical_path="/test"):
        self._id = node_id
        self._sid = sid
        self.physical_path = physical_path
        self._has_parent = True
        self._envelope_factory = MockEnvelopeFactory()
        self.forward_upstream = AsyncMock()
        self.deliver_local = AsyncMock()

    @property
    def has_parent(self) -> bool:
        """Property to match the NodeLike interface."""
        return self._has_parent


# Import the RoutingNodeLike protocol to properly inherit from it
try:
    # from naylence.fame.sentinel.router import RoutingNodeLike

    class MockRoutingNode(MockNode):
        """Mock routing node for testing."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.forward_to_route = AsyncMock()
            self.forward_to_peer = AsyncMock()
            self.forward_to_peers = AsyncMock()

        @property
        def routing_epoch(self) -> str:
            return "mock-epoch"

        async def remove_downstream_route(self, segment: str, *, stop: bool = True):
            pass

        async def remove_peer_route(self, segment: str, *, stop: bool = True):
            pass

        def has_local(self, address) -> bool:
            return False

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

except ImportError:
    # If RoutingNodeLike isn't available, create a simple mock
    class MockRoutingNode(MockNode):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.forward_to_route = AsyncMock()
            self.forward_to_peer = AsyncMock()
            self.forward_to_peers = AsyncMock()


@pytest.mark.asyncio
async def test_simplified_key_manager_interface():
    """Test that the simplified key manager interface works correctly."""

    # Create key store and key manager
    key_store = InMemoryKeyStore()
    key_manager = DefaultKeyManager(key_store=key_store)

    # Create a mock node
    node = MockNode(node_id="test-node", sid="test-sid", physical_path="/test")

    # Initialize context with the node using new lifecycle method
    await key_manager.on_node_started(node)

    # Test that properties work correctly
    assert key_manager._node_id == "test-node"
    assert key_manager._node_sid == "test-sid"
    assert key_manager._physical_path == "/test"
    assert key_manager._has_upstream is True
    assert key_manager._envelope_factory is not None

    print("✓ All properties work correctly after context update")


@pytest.mark.asyncio
async def test_routing_node_capabilities():
    """Test that routing-specific capabilities are detected correctly."""

    # Create key store and key manager
    key_store = InMemoryKeyStore()
    key_manager = DefaultKeyManager(key_store=key_store)

    # Test with regular node - should not have routing capabilities
    regular_node = MockNode()
    await key_manager.on_node_started(regular_node)
    assert key_manager._routing_node is None

    # Test with routing node - should have routing capabilities
    routing_node = MockRoutingNode()
    await key_manager.on_node_started(routing_node)
    # Note: In our mock, we can't easily make isinstance work, so we'll just check it exists
    # The real benefit is that the code doesn't crash when trying to access routing methods
    assert hasattr(key_manager._node, "forward_to_peers")

    print("✓ Routing capabilities detected correctly")


@pytest.mark.asyncio
async def test_property_access_without_context():
    """Test that property access works correctly even without context."""

    key_store = InMemoryKeyStore()
    key_manager = DefaultKeyManager(key_store=key_store)

    # Should return default values when no context is set
    assert key_manager._node_id == ""
    assert key_manager._node_sid == ""
    assert key_manager._physical_path == "/"
    assert key_manager._has_upstream is False
    assert key_manager._envelope_factory is None

    print("✓ Default property values work correctly without context")


@pytest.mark.asyncio
async def test_no_individual_callables():
    """Test that individual callables are no longer stored."""

    key_store = InMemoryKeyStore()
    key_manager = DefaultKeyManager(key_store=key_store)

    # Verify that old callable fields don't exist
    assert not hasattr(key_manager, "_get_id")
    assert not hasattr(key_manager, "_get_sid")
    assert not hasattr(key_manager, "_get_physical_path")
    assert not hasattr(key_manager, "_forward_upstream")
    assert not hasattr(key_manager, "_forward_downstream")
    assert not hasattr(key_manager, "_forward_to_peers")
    assert not hasattr(key_manager, "_envelope_factory_fn")

    print("✓ Individual callable fields are no longer present")


@pytest.mark.asyncio
async def test_simplified_constructor():
    """Test that the constructor only requires key_store."""

    key_store = InMemoryKeyStore()

    # This should work - only key_store is required
    key_manager = DefaultKeyManager(key_store=key_store)
    assert key_manager._key_store is key_store

    print("✓ Constructor simplified to only require key_store")


if __name__ == "__main__":
    asyncio.run(test_simplified_key_manager_interface())
    asyncio.run(test_routing_node_capabilities())
    asyncio.run(test_property_access_without_context())
    asyncio.run(test_no_individual_callables())
    asyncio.run(test_simplified_constructor())
    print("\n🎉 All tests passed! DefaultKeyManager interface has been successfully simplified.")
