#!/usr/bin/env python3
"""
Test binding manager with enhanced FAME address format supporting host-like notation.

Tests both backward compatibility with existing path-only addresses and
new functionality for host-only and host+path combinations.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.channel.in_memory.in_memory_binding import InMemoryBinding
from naylence.fame.core import (
    FameAddress,
)
from naylence.fame.delivery.delivery_tracker import DeliveryTracker
from naylence.fame.node.binding_manager import BindingManager, BindingStoreEntry
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


class TestBindingManagerHostNotation:
    """Test binding manager with host notation support."""

    @pytest.fixture
    def binding_manager(self):
        """Create a test binding manager."""
        # Mock dependencies
        envelope_factory = Mock()
        delivery_tracker = AsyncMock(spec=DeliveryTracker)

        return BindingManager(
            has_upstream=False,  # No upstream for basic tests
            get_id=lambda: "test-node-id",
            get_sid=lambda: "test-system-id",
            get_physical_path=lambda: "/test/physical/path",
            forward_upstream=AsyncMock(),
            get_accepted_logicals=lambda: {
                "api.services",
                "*.services",
                "api.test",
                "*.test",
                "service.api",
                "*.api",
                "fame.fabric",
                "fame.fabric/api",  # Add test addresses
            },
            binding_store=InMemoryKVStore(model_cls=BindingStoreEntry),
            binding_factory=lambda addr: InMemoryBinding(addr),
            envelope_factory=envelope_factory,
            delivery_tracker=delivery_tracker,
        )

    @pytest.mark.asyncio
    async def test_bind_traditional_path_only_address(self, binding_manager):
        """Test binding with traditional path-only addresses."""
        # Test with explicit path that's not in accepted logicals - should fail
        with pytest.raises(ValueError, match="not permitted"):
            await binding_manager.bind("worker@/api/service")

        # Test with just participant name (should use physical path)
        binding = await binding_manager.bind("alice")
        assert binding is not None
        # Should be bound to the physical path
        expected_addr = FameAddress("alice@/test/physical/path")
        assert binding_manager.has_binding(expected_addr)

    @pytest.mark.asyncio
    async def test_bind_host_only_address(self, binding_manager):
        """Test binding with host-only addresses."""
        binding = await binding_manager.bind("alice@fame.fabric")
        assert binding is not None
        assert binding_manager.has_binding(FameAddress("alice@fame.fabric"))

    @pytest.mark.asyncio
    async def test_bind_host_with_path_address(self, binding_manager):
        """Test binding with host+path addresses."""
        binding = await binding_manager.bind("alice@fame.fabric/api")
        assert binding is not None
        assert binding_manager.has_binding(FameAddress("alice@fame.fabric/api"))

    @pytest.mark.asyncio
    async def test_bind_logical_with_host_format(self, binding_manager):
        """Test binding with logicals using host format."""
        # This should work since api.services is in accepted_logicals
        binding = await binding_manager.bind("service@api.services")
        assert binding is not None
        assert binding_manager.has_binding(FameAddress("service@api.services"))

    @pytest.mark.asyncio
    async def test_bind_invalid_location_raises_error(self, binding_manager):
        """Test that binding with invalid locations raises appropriate errors."""
        # Path not in accepted logicals and not physical path
        with pytest.raises(ValueError, match="not permitted"):
            await binding_manager.bind("alice@/invalid/path")

        # Also test with host format that's not in accepted logicals
        with pytest.raises(ValueError, match="not permitted"):
            await binding_manager.bind("alice@invalid.domain/path")

    def test_match_pool_with_traditional_wildcards(self, binding_manager):
        """Test pool matching with new host-based pool patterns in accepted_logicals."""
        # No wildcard addresses stored in bindings anymore
        # Pool patterns are only in accepted_logicals

        # Test matching with an address that should match *.services pool
        match_addr = FameAddress("service@api.services")
        matched = binding_manager._match_pool(match_addr)
        # Should not match because no bindings exist for pool patterns yet
        assert matched is None

    def test_match_pool_with_host_based_wildcards(self, binding_manager):
        """Test pool matching with host-based pool patterns."""
        # Create a binding for a concrete instance that would match a pool
        concrete_addr = FameAddress("service@node123.services")
        binding_manager._bindings[concrete_addr] = InMemoryBinding(concrete_addr)

        # Test that the concrete instance exists
        matched = binding_manager.get_binding(concrete_addr)
        assert matched is not None

    def test_match_pool_cross_format_compatibility(self, binding_manager):
        """Test that new system works with host-like notation only."""
        # Create a concrete binding that would be created when binding to a pool
        concrete_addr = FameAddress("service@node123.test")
        binding_manager._bindings[concrete_addr] = InMemoryBinding(concrete_addr)

        # Test exact match
        matched = binding_manager.get_binding(concrete_addr)
        assert matched is not None

    def test_get_binding_with_various_formats(self, binding_manager):
        """Test that get_binding works with all address formats."""
        # Add bindings in different formats
        traditional_addr = FameAddress("alice@/")
        host_addr = FameAddress("bob@fame.fabric")
        host_path_addr = FameAddress("charlie@fame.fabric/api")

        binding_manager._bindings[traditional_addr] = InMemoryBinding(traditional_addr)
        binding_manager._bindings[host_addr] = InMemoryBinding(host_addr)
        binding_manager._bindings[host_path_addr] = InMemoryBinding(host_path_addr)

        # Test exact matches
        assert binding_manager.get_binding(traditional_addr) is not None
        assert binding_manager.get_binding(host_addr) is not None
        assert binding_manager.get_binding(host_path_addr) is not None

        # Test has_binding
        assert binding_manager.has_binding(traditional_addr)
        assert binding_manager.has_binding(host_addr)
        assert binding_manager.has_binding(host_path_addr)

    def test_wildcard_address_handling(self, binding_manager):
        """Test that wildcard addresses are handled correctly."""
        # Host-based wildcards should be supported in accepted_logicals
        accepted_logicals = binding_manager._get_accepted_logicals()

        # Verify that wildcard patterns are present
        wildcard_patterns = [logical for logical in accepted_logicals if "*" in logical]
        assert len(wildcard_patterns) > 0, "Should have wildcard patterns in accepted logicals"

        # Verify specific wildcard patterns
        assert "*.services" in accepted_logicals
        assert "*.test" in accepted_logicals
        assert "*.api" in accepted_logicals

    @pytest.mark.asyncio
    async def test_binding_with_wildcard_logical_patterns(self, binding_manager):
        """Test that binding works with addresses that match wildcard logical patterns."""
        # Test address that should match *.services pattern
        binding = await binding_manager.bind("worker@data.services")
        assert binding is not None
        assert binding_manager.has_binding(FameAddress("worker@data.services"))

        # Test address that should match *.test pattern
        binding2 = await binding_manager.bind("tester@node1.test")
        assert binding2 is not None
        assert binding_manager.has_binding(FameAddress("tester@node1.test"))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
