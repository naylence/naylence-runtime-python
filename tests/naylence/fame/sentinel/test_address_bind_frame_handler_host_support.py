#!/usr/bin/env python3
"""
Test address bind frame handler with host-based address support.

Tests that the address bind frame handler correctly processes both:
- Legacy path-based pool patterns like math@/api/*
- New host-based pool patterns like math@*.fame.fabric
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import (
    AddressBindFrame,
    AddressUnbindFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    generate_id,
)
from naylence.fame.sentinel.address_bind_frame_handler import AddressBindFrameHandler
from naylence.fame.sentinel.route_manager import RouteManager


class TestAddressBindFrameHandler:
    """Test address bind frame handler with host-based address support."""

    @pytest.fixture
    def handler(self):
        """Create test address bind frame handler."""
        # Mock dependencies
        routing_node = Mock()
        routing_node.forward_to_route = AsyncMock()
        routing_node.forward_upstream = AsyncMock()
        routing_node.forward_to_peers = AsyncMock()
        routing_node.envelope_factory = Mock()

        route_manager = Mock(spec=RouteManager)
        route_manager.downstream_routes = {"test-system"}
        route_manager._peer_routes = {"peer-system"}
        route_manager._downstream_addresses_routes = {}
        route_manager._downstream_addresses_legacy = {}
        route_manager._peer_addresses_routes = {}

        upstream_connector = Mock(return_value=True)

        return AddressBindFrameHandler(
            routing_node=routing_node,
            route_manager=route_manager,
            upstream_connector=upstream_connector,
        )

    @pytest.mark.asyncio
    async def test_bind_host_based_pool_address(self, handler):
        """Test binding to host-based pool addresses like math@*.fame.fabric."""
        # Create bind frame for host-based pool
        frame = AddressBindFrame(
            address="math@*.fame.fabric",
            corr_id=generate_id(),
            physical_path="/test/path",
        )

        envelope = Mock()
        envelope.frame = frame

        context = FameDeliveryContext(
            from_system_id="test-system", origin_type=DeliveryOriginType.DOWNSTREAM
        )

        await handler.accept_address_bind(envelope, context)

        # Verify pool was created with correct key
        pool_key = ("math", "*.fame.fabric")  # Full wildcard pattern
        assert pool_key in handler.pools
        assert "test-system" in handler.pools[pool_key]

    @pytest.mark.asyncio
    async def test_bind_exact_host_based_address(self, handler):
        """Test binding to exact host-based addresses like math@fame.fabric."""
        # Create bind frame for exact host-based address
        frame = AddressBindFrame(
            address="math@fame.fabric",
            corr_id=generate_id(),
            physical_path="/test/path",
        )

        envelope = Mock()
        envelope.frame = frame

        context = FameDeliveryContext(
            from_system_id="test-system", origin_type=DeliveryOriginType.DOWNSTREAM
        )

        await handler.accept_address_bind(envelope, context)

        # Verify exact address route was created
        assert "math@fame.fabric" in handler._route_manager._downstream_addresses_routes
        # Should not create any pools
        assert len(handler.pools) == 0

    @pytest.mark.asyncio
    async def test_unbind_host_based_pool_address(self, handler):
        """Test unbinding from host-based pool addresses."""
        # First bind to create the pool
        await self.test_bind_host_based_pool_address(handler)

        # Create unbind frame
        frame = AddressUnbindFrame(
            address="math@*.fame.fabric",
            corr_id=generate_id(),
        )

        envelope = Mock()
        envelope.frame = frame

        context = FameDeliveryContext(
            from_system_id="test-system", origin_type=DeliveryOriginType.DOWNSTREAM
        )

        await handler.accept_address_unbind(envelope, context)

        # Verify pool was removed
        pool_key = ("math", "*.fame.fabric")  # Full wildcard pattern
        assert pool_key not in handler.pools


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
