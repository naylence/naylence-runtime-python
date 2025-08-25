#!/usr/bin/env python3
"""
Complete integration test of wildcard and pool address functionality.

Tests the full wildcard address system including creation, validation,
pool matching, and edge cases.
"""

import pytest

from naylence.fame.core.address import (
    FameAddress,
    format_address_from_components,
)
from naylence.fame.util.logicals_util import (
    extract_pool_address_base,
    is_pool_address,
    matches_pool_address,
)


class TestWildcardAddressIntegration:
    """Integration tests for wildcard address functionality."""

    def test_wildcard_address_creation(self):
        """Test that wildcard addresses can be created and validated."""
        # Test basic wildcard host address
        addr = FameAddress("math@*.fame.fabric")
        assert str(addr) == "math@*.fame.fabric"

        # Test format function
        addr2 = format_address_from_components("service", host="*.api.fame.fabric")
        assert str(addr2) == "service@*.api.fame.fabric"

    def test_pool_matching(self):
        """Test that pool address matching works correctly."""
        # Host-based pool matching
        pool_pattern = "math@*.fame.fabric"

        # Should match subdomains
        assert matches_pool_address("math@node1.fame.fabric", pool_pattern)
        assert matches_pool_address("math@api.fame.fabric", pool_pattern)

        # Should match base domain
        assert matches_pool_address("math@fame.fabric", pool_pattern)

        # Should not match different participant
        assert not matches_pool_address("physics@node1.fame.fabric", pool_pattern)

        # Should not match different base domain
        assert not matches_pool_address("math@node1.other.fabric", pool_pattern)

        # Host+path matching (wildcards in host only)
        host_path_pool = "math@*.fame.fabric/api"
        assert matches_pool_address("math@node1.fame.fabric/api", host_path_pool)
        assert not matches_pool_address("math@node1.fame.fabric/other", host_path_pool)

    def test_pool_base_extraction(self):
        """Test pool base extraction."""
        # Host-based pool
        pool_addr = "math@*.fame.fabric"
        base = extract_pool_address_base(pool_addr)
        assert base == "math@fame.fabric"

        # Host-based pool with path
        pool_addr2 = "math@*.fame.fabric/api"
        base2 = extract_pool_address_base(pool_addr2)
        assert base2 == "math@fame.fabric/api"

        # Non-pool address
        regular = "math@node1.fame.fabric"
        regular_base = extract_pool_address_base(regular)
        assert regular_base is None

    def test_pool_detection(self):
        """Test pool address detection."""
        # Pool addresses (only host-based wildcards supported)
        assert is_pool_address("math@*.fame.fabric")
        assert is_pool_address("math@*.fame.fabric/api")

        # Regular addresses
        assert not is_pool_address("math@node1.fame.fabric")
        assert not is_pool_address("api@service.domain/endpoints/users")
        assert not is_pool_address("legacy@/services/auth")

    def test_validation_edge_cases(self):
        """Test validation edge cases."""
        # Test invalid wildcard positions
        with pytest.raises(ValueError):
            FameAddress("math@fame.*.fabric")  # Wildcard not in leftmost position

        with pytest.raises(ValueError):
            FameAddress("math@fame.fabric.*")  # Wildcard not in leftmost position

        # Test valid leftmost wildcard
        valid_addr = FameAddress("math@*.sub.fame.fabric")
        assert str(valid_addr) == "math@*.sub.fame.fabric"

    def test_wildcard_restrictions(self):
        """Test that wildcards are properly restricted to host parts only."""
        # Host wildcards should work
        valid_addresses = [
            "math@*.fame.fabric",
            "api@*.service.domain",
            "worker@*.compute.cluster/tasks",
        ]

        for addr_str in valid_addresses:
            addr = FameAddress(addr_str)
            assert str(addr) == addr_str

        # Path wildcards should be rejected
        invalid_addresses = [
            "math@fame.fabric/api/*",
            "worker@service.domain/jobs/*",
            "legacy@/services/*",
        ]

        for addr_str in invalid_addresses:
            with pytest.raises(ValueError):
                FameAddress(addr_str)

    def test_pool_routing_integration(self):
        """Test integration between pool addresses and routing logic."""
        # Test that pool patterns work with various target addresses
        pool_pattern = "math@*.fame.fabric"

        test_cases = [
            ("math@node1.fame.fabric", True),
            ("math@api.fame.fabric", True),
            ("math@compute.fame.fabric", True),
            ("math@fame.fabric", True),  # Base domain
            ("physics@node1.fame.fabric", False),  # Different participant
            ("math@node1.other.domain", False),  # Different domain
        ]

        for target_addr, should_match in test_cases:
            result = matches_pool_address(target_addr, pool_pattern)
            assert result == should_match, f"Address {target_addr} should {
                'match' if should_match else 'not match'
            } pool {pool_pattern}"

    def test_complex_host_patterns(self):
        """Test complex host patterns with multiple segments."""
        # Multi-segment wildcard patterns
        complex_pool = "service@*.api.fame.fabric"

        # Should match
        assert matches_pool_address("service@v1.api.fame.fabric", complex_pool)
        assert matches_pool_address("service@gateway.api.fame.fabric", complex_pool)
        assert matches_pool_address("service@api.fame.fabric", complex_pool)  # Base

        # Should not match
        assert not matches_pool_address("service@v1.other.fame.fabric", complex_pool)
        assert not matches_pool_address("other@v1.api.fame.fabric", complex_pool)

    def test_address_formatting_consistency(self):
        """Test that address formatting is consistent across creation methods."""
        # Create address via constructor
        addr1 = FameAddress("math@*.fame.fabric/api")

        # Create address via format function
        addr2 = format_address_from_components("math", host="*.fame.fabric", path="/api")

        # Should be equivalent
        assert str(addr1) == str(addr2)
        assert str(addr1) == "math@*.fame.fabric/api"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
