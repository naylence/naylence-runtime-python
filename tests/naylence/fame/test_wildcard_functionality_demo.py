"""
Demonstration and validation test for host-only wildcard functionality.

This test serves as both documentation and validation that wildcards
are properly restricted to host parts only.
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


class TestWildcardFunctionalityDemo:
    """Demonstration test for host-only wildcard functionality."""

    def test_supported_host_wildcards(self):
        """Test that host-based wildcards are properly supported."""
        # Valid host wildcard examples
        valid_examples = [
            ("math@*.fame.fabric", "math@fame.fabric"),
            ("api@*.service.domain", "api@service.domain"),
            ("worker@*.compute.cluster", "worker@compute.cluster"),
            (
                "db@*.data.fabric/readonly",
                "db@data.fabric/readonly",
            ),  # Host wildcard with path
        ]

        for addr_str, expected_base in valid_examples:
            # Should create successfully
            addr = FameAddress(addr_str)
            assert str(addr) == addr_str

            # Should be detected as pool address
            assert is_pool_address(addr_str)

            # Should extract correct base
            base = extract_pool_address_base(addr_str)
            assert base == expected_base

    def test_rejected_path_wildcards(self):
        """Test that path-based wildcards are properly rejected."""
        # Invalid path wildcard examples (should be rejected)
        invalid_examples = [
            "math@fame.fabric/api/*",
            "worker@service.domain/jobs/*",
            "legacy@/services/*",
            "api@/endpoints/*",
        ]

        for addr_str in invalid_examples:
            with pytest.raises(ValueError, match="Wildcards not allowed in path segments"):
                FameAddress(addr_str)

    def test_pool_matching_behavior(self):
        """Test pool matching behavior with wildcards."""
        pool_pattern = "math@*.fame.fabric"

        # Test cases: (address, should_match)
        test_cases = [
            ("math@node1.fame.fabric", True),  # Should match
            ("math@api.fame.fabric", True),  # Should match
            ("math@fame.fabric", True),  # Base domain should match
            ("physics@node1.fame.fabric", False),  # Different participant
            ("math@node1.other.fabric", False),  # Different domain
        ]

        for test_addr, should_match in test_cases:
            matches = matches_pool_address(test_addr, pool_pattern)
            assert matches == should_match, (
                f"Address {test_addr} should {'match' if should_match else 'not match'} pool {pool_pattern}"
            )

    def test_host_path_matching(self):
        """Test host+path matching behavior."""
        host_path_pool = "math@*.fame.fabric/api"

        # Test cases: (address, should_match)
        test_cases = [
            ("math@node1.fame.fabric/api", True),  # Should match
            ("math@api.fame.fabric/api", True),  # Should match
            ("math@node1.fame.fabric/other", False),  # Different path
        ]

        for test_addr, should_match in test_cases:
            matches = matches_pool_address(test_addr, host_path_pool)
            assert matches == should_match, f"Address {test_addr} should {
                'match' if should_match else 'not match'
            } pool {host_path_pool}"

    def test_wildcard_position_restrictions(self):
        """Test that wildcards are only allowed in leftmost host position."""
        # Valid: leftmost wildcard
        valid_addr = FameAddress("math@*.sub.fame.fabric")
        assert str(valid_addr) == "math@*.sub.fame.fabric"

        # Invalid: non-leftmost wildcards
        invalid_patterns = [
            "math@fame.*.fabric",  # Middle position
            "math@fame.fabric.*",  # Rightmost position
            "math@*.*.fabric",  # Multiple wildcards
        ]

        for pattern in invalid_patterns:
            with pytest.raises(ValueError):
                FameAddress(pattern)

    def test_format_function_consistency(self):
        """Test that formatting functions work consistently with wildcards."""
        # Test format_address_from_components
        addr1 = FameAddress("service@*.api.fame.fabric/endpoint")
        addr2 = format_address_from_components("service", host="*.api.fame.fabric", path="/endpoint")

        assert str(addr1) == str(addr2)
        assert str(addr1) == "service@*.api.fame.fabric/endpoint"

    def test_wildcard_functionality_summary(self):
        """Test that demonstrates the complete wildcard functionality."""
        # Summary of what should work and what shouldn't

        # ✅ SHOULD WORK: Host-based wildcards
        working_examples = [
            "math@*.fame.fabric",
            "api@*.service.domain",
            "worker@*.compute.cluster/tasks",
            "db@*.data.fabric/readonly",
        ]

        for example in working_examples:
            FameAddress(example)  # Should not raise
            assert is_pool_address(example)  # Should be pool address

        # 🚫 SHOULD NOT WORK: Path-based wildcards
        failing_examples = [
            "math@fame.fabric/api/*",
            "worker@service.domain/jobs/*",
            "legacy@/services/*",
            "api@/endpoints/*",
        ]

        for example in failing_examples:
            with pytest.raises(ValueError):
                FameAddress(example)

    def test_documentation_compliance(self):
        """Test that implementation matches documentation requirements."""
        # Requirements from the migration:
        # 1. Wildcards (*) are ONLY supported in the leftmost position of host segments
        # 2. Path segments do NOT support wildcards
        # 3. Pool matching works with host-based wildcards
        # 4. Host+path addresses require exact path matches when host has wildcards

        # Requirement 1: Leftmost host wildcard only
        FameAddress("service@*.domain.com")  # Should work
        with pytest.raises(ValueError):
            FameAddress("service@sub.*.com")  # Should fail

        # Requirement 2: No path wildcards
        with pytest.raises(ValueError):
            FameAddress("service@domain.com/path/*")  # Should fail

        # Requirement 3: Pool matching with host wildcards
        assert matches_pool_address("service@sub.domain.com", "service@*.domain.com")

        # Requirement 4: Exact path matching required
        assert matches_pool_address("service@sub.domain.com/exact", "service@*.domain.com/exact")
        assert not matches_pool_address("service@sub.domain.com/different", "service@*.domain.com/exact")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
