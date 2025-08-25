"""
Test for the key correlation map functionality.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyAnnounceFrame,
    KeyRequestFrame,
)
from naylence.fame.sentinel.key_correlation_map import KeyCorrelationMap
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler


class TestKeyCorrelationMap:
    """Test suite for KeyCorrelationMap."""

    def test_add_and_pop(self):
        """Test basic add and pop functionality."""
        corr_map = KeyCorrelationMap(ttl_sec=30)

        # Add a mapping
        corr_map.add("test-corr-1", "route-a")

        # Pop it back
        route = corr_map.pop("test-corr-1")
        assert route == "route-a"

        # Second pop should return None
        route = corr_map.pop("test-corr-1")
        assert route is None

    def test_ttl_expiry(self):
        """Test TTL expiry functionality."""
        corr_map = KeyCorrelationMap(ttl_sec=0.1)  # Very short TTL for testing

        # Add a mapping
        corr_map.add("test-corr-1", "route-a")

        # Should still be there immediately
        route = corr_map.pop("test-corr-1")
        assert route == "route-a"

        # Add again and wait for expiry
        corr_map.add("test-corr-2", "route-b")
        import time

        time.sleep(0.2)  # Wait longer than TTL

        route = corr_map.pop("test-corr-2")
        assert route is None

    def test_lru_eviction(self):
        """Test LRU eviction."""
        corr_map = KeyCorrelationMap(ttl_sec=30, max_entries=2)

        # Add 3 entries (should evict the first)
        corr_map.add("corr-1", "route-1")
        corr_map.add("corr-2", "route-2")
        corr_map.add("corr-3", "route-3")

        # First entry should be evicted
        assert corr_map.pop("corr-1") is None

        # Other entries should still be there
        assert corr_map.pop("corr-2") == "route-2"
        assert corr_map.pop("corr-3") == "route-3"

    @pytest.mark.asyncio
    async def test_cleanup_task(self):
        """Test the background cleanup task."""
        corr_map = KeyCorrelationMap(ttl_sec=0.1)

        # Add an entry
        corr_map.add("test-corr", "test-route")

        # Start cleanup task with very short interval
        cleanup_task = asyncio.create_task(corr_map.run_cleanup(interval=0.05))

        try:
            # Wait for entry to expire and get cleaned up
            await asyncio.sleep(0.2)

            # Entry should be gone
            assert corr_map.pop("test-corr") is None

        finally:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass


class TestKeyFrameHandlerCorrelation:
    """Test suite for KeyFrameHandler correlation functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.routing_node = MagicMock()
        self.routing_node.id = "test-sentinel"
        self.routing_node.physical_path = "/test/sentinel"
        self.routing_node.envelope_factory.create_envelope = MagicMock()
        self.routing_node.forward_to_route = AsyncMock()

        self.route_manager = MagicMock()
        self.route_manager.downstream_routes = {"child-1", "child-2"}
        self.route_manager._peer_routes = {}
        self.route_manager._downstream_addresses_routes = {}
        self.route_manager._peer_addresses_routes = {}

        self.binding_manager = MagicMock()
        self.binding_manager.get_binding.return_value = None

        self.key_manager = MagicMock()
        self.accept_key_announce_parent = AsyncMock()

        self.handler = KeyFrameHandler(
            routing_node=self.routing_node,
            route_manager=self.route_manager,
            binding_manager=self.binding_manager,
            accept_key_announce_parent=self.accept_key_announce_parent,
            key_manager=self.key_manager,
        )

    @pytest.mark.asyncio
    async def test_key_request_stores_correlation(self):
        """Test that key requests store correlation mapping for downstream routes."""
        from naylence.fame.sentinel.route_manager import AddressRouteInfo

        # Set up downstream route
        test_address = FameAddress("agent@*.fame.fabric")
        route_info = AddressRouteInfo(segment="child-1", physical_path="/child/1", encryption_key_id=None)
        self.route_manager._downstream_addresses_routes[test_address] = route_info

        # Create key request
        frame = KeyRequestFrame(address=test_address, physical_path=None)

        envelope = MagicMock()
        envelope.frame = frame
        envelope.corr_id = "test-correlation-123"

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-2")

        # Process the request
        result = await self.handler.accept_key_request(envelope, context)

        # Should have stored the correlation
        stored_route = self.handler._corr_map.pop("test-correlation-123")
        assert stored_route == "child-2"

        # Should return False to indicate routing needed (goes through pipeline now)
        assert result is False, "Expected False to indicate routing needed"

        # Should NOT have called direct forwarding (routing pipeline handles it now)
        self.routing_node.forward_to_route.assert_not_called()

    @pytest.mark.asyncio
    async def test_key_announce_routes_back(self):
        """Test that key announces route back to original requester."""
        # Store a correlation mapping
        self.handler._corr_map.add("test-correlation-456", "child-2")

        # Create key announce with matching correlation ID
        frame = KeyAnnounceFrame(
            physical_path="/child/1",
            keys=[{"kid": "test-key", "use": "enc"}],
        )

        envelope = MagicMock()
        envelope.frame = frame
        envelope.corr_id = "test-correlation-456"

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Process the announce
        await self.handler.accept_key_announce(envelope, context)

        # Should have routed back to child-2 with a re-signed envelope
        # (The Sentinel creates a new envelope with its own SID for trust chain)
        self.routing_node.forward_to_route.assert_called_once()
        call_args = self.routing_node.forward_to_route.call_args
        assert call_args[0][0] == "child-2"  # routed to child-2
        assert call_args[0][2] == context  # same context
        # The envelope should be newly created (re-signed), not the original
        assert call_args[0][1] != envelope  # different envelope object

        # Should not have called parent handler
        self.accept_key_announce_parent.assert_not_called()

        # Correlation should be consumed (popped)
        assert self.handler._corr_map.pop("test-correlation-456") is None

    @pytest.mark.asyncio
    async def test_key_announce_fallback_to_parent(self):
        """Test that key announces without correlation fall back to parent handler."""
        # Create key announce without correlation ID
        frame = KeyAnnounceFrame(
            physical_path="/child/1",
            keys=[{"kid": "test-key", "use": "enc"}],
            # No corr_id
        )

        envelope = MagicMock()
        envelope.frame = frame

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Process the announce
        await self.handler.accept_key_announce(envelope, context)

        # Should not have tried to route
        self.routing_node.forward_to_route.assert_not_called()

        # Should have called parent handler
        self.accept_key_announce_parent.assert_called_once_with(envelope, context)
