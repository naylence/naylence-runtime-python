#!/usr/bin/env python3
"""
Test wildcard pool address support in FAME core.

Tests the enhanced wildcard support for pool addresses including:
- FameAddress validation allowing leftmost wildcards
- matches_pool_logical allowing base domain matching
- Address bind frame handler supporting host-based addresses
- Certificate infrastructure using proper DNS constraints
"""

import pytest

from naylence.fame.core import (
    FameAddress,
    format_address,
    parse_address,
)
from naylence.fame.util.logicals_util import extract_pool_base, is_pool_logical, matches_pool_logical


class TestWildcardPoolAddresses:
    """Test wildcard pool address functionality."""

    def test_fame_address_accepts_leftmost_wildcards(self):
        """Test that FameAddress allows leftmost wildcards like math@*.fame.fabric."""
        # Should work with leftmost wildcards
        addr1 = FameAddress("math@*.fame.fabric")
        assert str(addr1) == "math@*.fame.fabric"

        addr2 = FameAddress("service@*.api.domain")
        assert str(addr2) == "service@*.api.domain"

        # Should still work with regular addresses
        addr3 = FameAddress("math@fame.fabric")
        assert str(addr3) == "math@fame.fabric"

    def test_fame_address_rejects_non_leftmost_wildcards(self):
        """Test that wildcards are only allowed in leftmost position."""
        # Should reject wildcards not in leftmost position
        with pytest.raises(ValueError, match="must be leftmost"):
            FameAddress("math@api.*.domain")

        with pytest.raises(ValueError, match="must be leftmost"):
            FameAddress("math@api.domain.*")

    def test_parse_address_handles_wildcards(self):
        """Test that parse_address works with wildcard addresses."""
        name, location = parse_address("math@*.fame.fabric")
        assert name == "math"
        assert location == "*.fame.fabric"

        name, location = parse_address("service@*.api.domain")
        assert name == "service"
        assert location == "*.api.domain"

    def test_format_address_handles_wildcards(self):
        """Test that format_address works with wildcard locations."""
        addr = format_address("math", "*.fame.fabric")
        assert addr == "math@*.fame.fabric"

        addr = format_address("service", "*.api.domain")
        assert addr == "service@*.api.domain"

    def test_is_pool_logical_detects_wildcards(self):
        """Test that is_pool_logical correctly identifies wildcard patterns."""
        assert is_pool_logical("*.fame.fabric") is True
        assert is_pool_logical("*.api.services") is True
        assert is_pool_logical("fame.fabric") is False
        assert is_pool_logical("api.services") is False

    def test_matches_pool_logical_allows_base_domain_matching(self):
        """Test that matches_pool_logical allows both subdomain and base domain matching."""
        # Base domain should match pool pattern
        assert matches_pool_logical("fame.fabric", "*.fame.fabric") is True
        assert matches_pool_logical("api.services", "*.api.services") is True

        # Subdomains should still match
        assert matches_pool_logical("node1.fame.fabric", "*.fame.fabric") is True
        assert matches_pool_logical("worker.api.services", "*.api.services") is True

        # Non-matching domains should not match
        assert matches_pool_logical("other.domain", "*.fame.fabric") is False
        assert matches_pool_logical("completely.different", "*.api.services") is False

    def test_extract_pool_base_works_with_wildcards(self):
        """Test that extract_pool_base correctly extracts base from wildcard patterns."""
        assert extract_pool_base("*.fame.fabric") == "fame.fabric"
        assert extract_pool_base("*.api.services") == "api.services"
        assert extract_pool_base("fame.fabric") is None  # Not a pool pattern
