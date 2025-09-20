"""
Comprehensive tests for logicals_util module.

This test file targets systematic coverage improvement for the logicals_util module,
focusing on the largest gaps first to maximize coverage impact.
"""

import os
from unittest.mock import patch

import pytest

from naylence.fame.util.logicals_util import (
    convert_wildcard_logical_to_dns_constraint,
    create_host_logical_uri,
    create_logical_uri,
    extract_host_logical_from_uri,
    extract_logical_from_uri,
    extract_pool_base,
    get_fame_root,
    hostname_to_logical,
    hostnames_to_logicals,
    is_pool_logical,
    logical_patterns_to_dns_constraints,
    logical_to_hostname,
    logicals_to_hostnames,
    matches_pool_logical,
    validate_host_logical,
    validate_host_logicals,
    validate_logical,
    validate_logical_segment,
)


class TestValidateHostLogical:
    """Test validate_host_logical function - covers lines 344-412 (largest gap)."""

    def test_empty_host_logical(self):
        """Test validation of empty host logical."""
        is_valid, error = validate_host_logical("")
        assert not is_valid
        assert error == "Empty host logical"

    def test_valid_simple_hostname(self):
        """Test validation of simple valid hostname."""
        is_valid, error = validate_host_logical("api.service.domain")
        assert is_valid
        assert error is None

    def test_valid_single_label(self):
        """Test validation of single label hostname."""
        is_valid, error = validate_host_logical("localhost")
        assert is_valid
        assert error is None

    def test_valid_wildcard_leftmost(self):
        """Test validation of valid wildcard in leftmost position."""
        is_valid, error = validate_host_logical("*.fame.fabric")
        assert is_valid
        assert error is None

    def test_wildcard_not_leftmost(self):
        """Test rejection of wildcard not in leftmost position."""
        is_valid, error = validate_host_logical("fame.*.fabric")
        assert not is_valid
        assert "contains wildcard not in leftmost position" in error

    def test_wildcard_rightmost(self):
        """Test rejection of wildcard in rightmost position."""
        is_valid, error = validate_host_logical("fame.fabric.*")
        assert not is_valid
        assert "contains wildcard not in leftmost position" in error

    def test_multiple_wildcards(self):
        """Test rejection of multiple wildcards."""
        is_valid, error = validate_host_logical("*.*.fabric")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_wildcard_without_base_domain(self):
        """Test rejection of wildcard without base domain."""
        is_valid, error = validate_host_logical("*.")
        assert not is_valid
        assert "has wildcard but no base domain" in error

    def test_wildcard_with_invalid_base_domain(self):
        """Test rejection of wildcard with invalid base domain."""
        is_valid, error = validate_host_logical("*.invalid..domain")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_wildcard_exceeds_length_limit(self):
        """Test rejection of wildcard hostname exceeding 253 characters."""
        long_domain = "*.very-" + "long-" * 50 + "domain.com"
        is_valid, error = validate_host_logical(long_domain)
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_wildcard_invalid_label(self):
        """Test rejection of wildcard with invalid label in base domain."""
        is_valid, error = validate_host_logical("*.-invalid.domain")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_non_wildcard_invalid_hostname(self):
        """Test rejection of non-wildcard invalid hostname."""
        is_valid, error = validate_host_logical("invalid..hostname")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_non_wildcard_exceeds_length_limit(self):
        """Test rejection of non-wildcard hostname exceeding 253 characters."""
        long_hostname = "very-" + "long-" * 50 + "hostname.com"
        is_valid, error = validate_host_logical(long_hostname)
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_non_wildcard_invalid_label(self):
        """Test rejection of non-wildcard hostname with invalid label."""
        is_valid, error = validate_host_logical("-invalid.domain")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_label_starts_with_hyphen(self):
        """Test rejection of label starting with hyphen."""
        is_valid, error = validate_host_logical("valid.-starts-hyphen")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_label_ends_with_hyphen(self):
        """Test rejection of label ending with hyphen."""
        is_valid, error = validate_host_logical("valid.ends-hyphen-")
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_label_exceeds_63_characters(self):
        """Test rejection of label exceeding 63 characters."""
        long_label = "a" * 64
        hostname = f"valid.{long_label}.domain"
        is_valid, error = validate_host_logical(hostname)
        assert not is_valid
        assert "contains invalid label" in error

    def test_edge_case_valid_63_char_label(self):
        """Test acceptance of label exactly 63 characters."""
        valid_label = "a" * 63
        hostname = f"valid.{valid_label}.domain"
        is_valid, error = validate_host_logical(hostname)
        assert is_valid
        assert error is None

    def test_valid_hostname_with_numbers(self):
        """Test validation of hostname with numbers."""
        is_valid, error = validate_host_logical("api1.service2.domain3")
        assert is_valid
        assert error is None

    def test_valid_hostname_with_hyphens(self):
        """Test validation of hostname with hyphens."""
        is_valid, error = validate_host_logical("api-service.test-domain.com")
        assert is_valid
        assert error is None


class TestValidateHostLogicals:
    """Test validate_host_logicals function for list validation."""

    def test_empty_list(self):
        """Test validation of empty list."""
        is_valid, error = validate_host_logicals([])
        assert is_valid
        assert error is None

    def test_all_valid_logicals(self):
        """Test validation of list with all valid host logicals."""
        host_logicals = ["api.service.domain", "*.fame.fabric", "localhost"]
        is_valid, error = validate_host_logicals(host_logicals)
        assert is_valid
        assert error is None

    def test_first_invalid_logical(self):
        """Test validation stops at first invalid logical."""
        host_logicals = ["invalid..hostname", "api.service.domain"]
        is_valid, error = validate_host_logicals(host_logicals)
        assert not is_valid
        assert "is not a valid DNS hostname" in error

    def test_mixed_valid_invalid_logicals(self):
        """Test validation with mix of valid and invalid logicals."""
        host_logicals = ["api.service.domain", "*.invalid..domain"]
        is_valid, error = validate_host_logicals(host_logicals)
        assert not is_valid
        assert "is not a valid DNS hostname" in error


class TestValidateLogicalSegment:
    """Test validate_logical_segment function - covers lines 59-83."""

    def test_empty_segment(self):
        """Test validation of empty segment."""
        is_valid, error = validate_logical_segment("")
        assert not is_valid
        assert error == "Empty path segment"

    def test_valid_simple_segment(self):
        """Test validation of simple valid segment."""
        is_valid, error = validate_logical_segment("api")
        assert is_valid
        assert error is None

    def test_valid_alphanumeric_segment(self):
        """Test validation of alphanumeric segment."""
        is_valid, error = validate_logical_segment("api123")
        assert is_valid
        assert error is None

    def test_valid_segment_with_hyphens(self):
        """Test validation of segment with hyphens."""
        is_valid, error = validate_logical_segment("api-service")
        assert is_valid
        assert error is None

    def test_segment_exceeds_63_octets(self):
        """Test rejection of segment exceeding 63 octets."""
        long_segment = "a" * 64
        is_valid, error = validate_logical_segment(long_segment)
        assert not is_valid
        assert "exceeds 63 octets" in error

    def test_segment_with_invalid_characters(self):
        """Test rejection of segment with invalid characters."""
        is_valid, error = validate_logical_segment("api@service")
        assert not is_valid
        assert "contains invalid characters" in error

    def test_segment_starts_with_hyphen(self):
        """Test rejection of segment starting with hyphen."""
        is_valid, error = validate_logical_segment("-api")
        assert not is_valid
        assert "cannot start or end with hyphen" in error

    def test_segment_ends_with_hyphen(self):
        """Test rejection of segment ending with hyphen."""
        is_valid, error = validate_logical_segment("api-")
        assert not is_valid
        assert "cannot start or end with hyphen" in error

    def test_segment_consecutive_hyphens(self):
        """Test rejection of segment with consecutive hyphens."""
        is_valid, error = validate_logical_segment("api--service")
        assert not is_valid
        assert "cannot contain consecutive hyphens" in error

    def test_edge_case_exactly_63_octets(self):
        """Test acceptance of segment exactly 63 octets."""
        valid_segment = "a" * 63
        is_valid, error = validate_logical_segment(valid_segment)
        assert is_valid
        assert error is None


class TestValidateLogical:
    """Test validate_logical function - covers lines 98-128."""

    def test_empty_logical(self):
        """Test validation of empty logical."""
        is_valid, error = validate_logical("")
        assert not is_valid
        assert error == "Empty logical"

    def test_logical_without_leading_slash(self):
        """Test rejection of logical without leading slash."""
        is_valid, error = validate_logical("api/service")
        assert not is_valid
        assert "must start with '/'" in error

    def test_valid_root_logical(self):
        """Test validation of root logical."""
        is_valid, error = validate_logical("/")
        assert is_valid
        assert error is None

    def test_valid_simple_logical(self):
        """Test validation of simple logical."""
        is_valid, error = validate_logical("/api")
        assert is_valid
        assert error is None

    def test_valid_multi_segment_logical(self):
        """Test validation of multi-segment logical."""
        is_valid, error = validate_logical("/api/service/endpoint")
        assert is_valid
        assert error is None

    def test_logical_with_empty_segments(self):
        """Test rejection of logical with only empty segments."""
        is_valid, error = validate_logical("///")
        assert not is_valid
        assert "must contain at least one non-empty segment" in error

    def test_logical_with_invalid_segment(self):
        """Test rejection of logical with invalid segment."""
        is_valid, error = validate_logical("/api/-invalid")
        assert not is_valid
        assert "Invalid logical" in error
        assert "cannot start or end with hyphen" in error

    def test_logical_converts_to_long_hostname(self):
        """Test rejection of logical that converts to hostname exceeding 253 characters."""
        # Create a logical that will result in a very long hostname
        long_segments = ["a" * 60 for _ in range(5)]  # 5 segments of 60 chars each
        logical = "/" + "/".join(long_segments)
        is_valid, error = validate_logical(logical)
        assert not is_valid
        assert "converts to hostname exceeding 253 characters" in error


class TestGetFameRoot:
    """Test get_fame_root function."""

    def test_default_fame_root(self):
        """Test default FAME_ROOT value."""
        with patch.dict(os.environ, {}, clear=True):
            root = get_fame_root()
            assert root == "fame.fabric"

    def test_custom_fame_root(self):
        """Test custom FAME_ROOT from environment."""
        with patch.dict(os.environ, {"FAME_ROOT": "custom.domain"}):
            root = get_fame_root()
            assert root == "custom.domain"


class TestLogicalToHostname:
    """Test logical_to_hostname function."""

    def test_empty_logical_raises_error(self):
        """Test that empty logical raises ValueError."""
        with pytest.raises(ValueError, match="Empty logical"):
            logical_to_hostname("")

    def test_logical_without_slash_raises_error(self):
        """Test that logical without leading slash raises ValueError."""
        with pytest.raises(ValueError, match="cannot start with '/'"):
            logical_to_hostname("api/service")

    def test_root_logical_returns_fame_root(self):
        """Test that root logical returns FAME_ROOT."""
        with patch("naylence.fame.util.logicals_util.get_fame_root", return_value="test.fabric"):
            hostname = logical_to_hostname("/")
            assert hostname == "test.fabric"

    def test_logical_with_empty_segments_raises_error(self):
        """Test that logical with only empty segments raises ValueError."""
        with pytest.raises(ValueError, match="must contain at least one non-empty segment"):
            logical_to_hostname("///")

    def test_single_segment_logical(self):
        """Test conversion of single segment logical."""
        hostname = logical_to_hostname("/api")
        assert hostname == "api"

    def test_multi_segment_logical(self):
        """Test conversion of multi-segment logical."""
        hostname = logical_to_hostname("/api/service/endpoint")
        assert hostname == "endpoint.service.api"

    def test_logical_with_empty_segments_ignored(self):
        """Test that empty segments are ignored during conversion."""
        hostname = logical_to_hostname("/api//service/")
        assert hostname == "service.api"


class TestExtractLogicalFromUri:
    """Test extract_logical_from_uri function - covers lines 270-294."""

    def test_non_naylence_uri(self):
        """Test rejection of non-naylence URI."""
        result = extract_logical_from_uri("https://example.com/path")
        assert result is None

    def test_empty_uri(self):
        """Test empty URI."""
        result = extract_logical_from_uri("")
        assert result is None

    def test_path_notation_uri(self):
        """Test path notation: naylence:///p1/p2/p3"""
        result = extract_logical_from_uri("naylence:///api/service/endpoint")
        assert result == "/api/service/endpoint"

    def test_path_notation_root(self):
        """Test path notation for root: naylence:///"""
        result = extract_logical_from_uri("naylence:///")
        assert result == "/"

    def test_hostname_notation_with_trailing_slash(self):
        """Test hostname notation: naylence://p3.p2.p1/"""
        result = extract_logical_from_uri("naylence://endpoint.service.api/")
        assert result == "/api/service/endpoint"

    def test_hostname_notation_invalid_hostname_with_slash(self):
        """Test hostname notation with invalid hostname and trailing slash."""
        result = extract_logical_from_uri("naylence://invalid..hostname/")
        assert result is None

    def test_hostname_notation_without_trailing_slash(self):
        """Test hostname notation without trailing slash."""
        result = extract_logical_from_uri("naylence://endpoint.service.api")
        assert result == "/api/service/endpoint"

    def test_hostname_notation_invalid_hostname_no_slash(self):
        """Test hostname notation with invalid hostname and no trailing slash."""
        result = extract_logical_from_uri("naylence://invalid..hostname")
        assert result is None

    def test_single_segment_no_dots_no_slash(self):
        """Test single segment without dots or slash - should be path notation."""
        result = extract_logical_from_uri("naylence://api")
        assert result == "/api"

    def test_segment_with_dots_invalid_hostname(self):
        """Test segment with dots but invalid as hostname."""
        result = extract_logical_from_uri("naylence://api..")
        assert result is None


class TestExtractHostLogicalFromUri:
    """Test extract_host_logical_from_uri function - covers lines 307-326."""

    def test_non_naylence_uri(self):
        """Test rejection of non-naylence URI."""
        result = extract_host_logical_from_uri("https://example.com/")
        assert result is None

    def test_path_notation_to_hostname(self):
        """Test path notation converted to hostname."""
        result = extract_host_logical_from_uri("naylence:///api/service")
        assert result == "service.api"

    def test_path_notation_invalid_logical(self):
        """Test path notation with invalid logical - conversion still works."""
        result = extract_host_logical_from_uri("naylence:///api/-invalid")
        # The conversion happens anyway, even with invalid segments
        assert result == "-invalid.api"

    def test_hostname_notation_with_trailing_slash(self):
        """Test hostname notation with trailing slash."""
        result = extract_host_logical_from_uri("naylence://fame.fabric/")
        assert result == "fame.fabric"

    def test_hostname_notation_empty_with_slash(self):
        """Test empty hostname with trailing slash."""
        result = extract_host_logical_from_uri("naylence:///")
        # This converts path "/" to hostname, which should be FAME_ROOT
        with patch("naylence.fame.util.logicals_util.get_fame_root", return_value="fame.fabric"):
            result = extract_host_logical_from_uri("naylence:///")
            assert result == "fame.fabric"

    def test_hostname_notation_without_trailing_slash(self):
        """Test hostname notation without trailing slash."""
        result = extract_host_logical_from_uri("naylence://fame.fabric")
        assert result == "fame.fabric"

    def test_empty_hostname_no_slash(self):
        """Test empty hostname without slash."""
        result = extract_host_logical_from_uri("naylence://")
        assert result is None


class TestCreateLogicalUri:
    """Test create_logical_uri function - covers missing lines."""

    def test_path_notation_default(self):
        """Test default path notation."""
        result = create_logical_uri("/api/service")
        assert result == "naylence:///api/service"

    def test_hostname_notation_enabled(self):
        """Test hostname notation when enabled."""
        result = create_logical_uri("/api/service", use_hostname_notation=True)
        assert result == "naylence://service.api/"

    def test_root_logical_path_notation(self):
        """Test root logical with path notation."""
        result = create_logical_uri("/")
        assert result == "naylence:///"

    def test_root_logical_hostname_notation(self):
        """Test root logical with hostname notation."""
        with patch("naylence.fame.util.logicals_util.get_fame_root", return_value="fame.fabric"):
            result = create_logical_uri("/", use_hostname_notation=True)
            assert result == "naylence://fame.fabric/"


class TestCreateHostLogicalUri:
    """Test create_host_logical_uri function."""

    def test_simple_host_logical(self):
        """Test simple host logical URI creation."""
        result = create_host_logical_uri("api.service.domain")
        assert result == "naylence://api.service.domain/"

    def test_wildcard_host_logical(self):
        """Test wildcard host logical URI creation."""
        result = create_host_logical_uri("*.service.domain")
        assert result == "naylence://*.service.domain/"


class TestConvertWildcardLogicalToDnsConstraint:
    """Test convert_wildcard_logical_to_dns_constraint function."""

    def test_simple_logical_no_wildcard(self):
        """Test simple logical without wildcard."""
        result = convert_wildcard_logical_to_dns_constraint("api.service.domain")
        assert result == "api.service.domain"

    def test_wildcard_logical(self):
        """Test wildcard logical conversion."""
        result = convert_wildcard_logical_to_dns_constraint("*.service.domain")
        assert result == ".service.domain"


class TestLogicalPatternsToDnsConstraints:
    """Test logical_patterns_to_dns_constraints function."""

    def test_empty_list(self):
        """Test empty pattern list."""
        result = logical_patterns_to_dns_constraints([])
        assert result == []

    def test_mixed_patterns(self):
        """Test mixed wildcard and non-wildcard patterns."""
        patterns = ["api.service.domain", "*.service.domain", "test.domain"]
        result = logical_patterns_to_dns_constraints(patterns)
        expected = ["api.service.domain", ".service.domain", "test.domain"]
        assert result == expected


class TestIsPoolLogical:
    """Test is_pool_logical function."""

    def test_non_wildcard_logical(self):
        """Test non-wildcard logical."""
        result = is_pool_logical("api.service.domain")
        assert result is False

    def test_wildcard_logical(self):
        """Test wildcard logical."""
        result = is_pool_logical("*.service.domain")
        assert result is True

    def test_empty_logical(self):
        """Test empty logical."""
        result = is_pool_logical("")
        assert result is False


class TestMatchesPoolLogical:
    """Test matches_pool_logical function."""

    def test_exact_match(self):
        """Test exact match - non-wildcard patterns return False."""
        result = matches_pool_logical("api.service.domain", "api.service.domain")
        assert result is False  # This is expected since the pattern is not a wildcard

    def test_wildcard_match(self):
        """Test wildcard match."""
        result = matches_pool_logical("api.service.domain", "*.service.domain")
        assert result is True

    def test_wildcard_no_match(self):
        """Test wildcard no match."""
        result = matches_pool_logical("api.different.domain", "*.service.domain")
        assert result is False

    def test_non_wildcard_pattern_no_match(self):
        """Test non-wildcard pattern that doesn't match."""
        result = matches_pool_logical("api.service.domain", "other.service.domain")
        assert result is False


class TestExtractPoolBase:
    """Test extract_pool_base function - covers lines 587-589."""

    def test_non_wildcard_logical(self):
        """Test non-wildcard logical."""
        result = extract_pool_base("api.service.domain")
        assert result is None

    def test_wildcard_logical(self):
        """Test wildcard logical extraction."""
        result = extract_pool_base("*.service.domain")
        assert result == "service.domain"

    def test_invalid_wildcard(self):
        """Test invalid wildcard format."""
        result = extract_pool_base("api.*.domain")
        assert result is None


class TestLogicalsToHostnames:
    """Test logicals_to_hostnames function - covers line 219."""

    def test_convert_multiple_logicals(self):
        """Test converting multiple logicals to hostnames."""
        logicals = ["/api", "/service/endpoint"]
        result = logicals_to_hostnames(logicals)
        expected = ["api", "endpoint.service"]
        assert result == expected

    def test_empty_list(self):
        """Test empty list conversion."""
        result = logicals_to_hostnames([])
        assert result == []


class TestHostnamesToLogicals:
    """Test hostnames_to_logicals function - covers line 235."""

    def test_convert_multiple_hostnames(self):
        """Test converting multiple hostnames to logicals."""
        hostnames = ["api", "endpoint.service"]
        result = hostnames_to_logicals(hostnames)
        expected = ["/api", "/service/endpoint"]
        assert result == expected

    def test_empty_list(self):
        """Test empty list conversion."""
        result = hostnames_to_logicals([])
        assert result == []


class TestHostnameToLogical:
    """Test hostname_to_logical function."""

    def test_empty_hostname_raises_error(self):
        """Test that empty hostname raises ValueError."""
        with pytest.raises(ValueError, match="Empty hostname"):
            hostname_to_logical("")

    def test_fame_root_returns_root_logical(self):
        """Test that FAME_ROOT hostname returns root logical."""
        with patch("naylence.fame.util.logicals_util.get_fame_root", return_value="test.fabric"):
            logical = hostname_to_logical("test.fabric")
            assert logical == "/"

    def test_hostname_with_empty_segments_raises_error(self):
        """Test that hostname with empty segments raises ValueError."""
        with pytest.raises(ValueError, match="contains empty segments"):
            hostname_to_logical("api..service")

    def test_single_label_hostname(self):
        """Test conversion of single label hostname."""
        logical = hostname_to_logical("api")
        assert logical == "/api"

    def test_multi_label_hostname(self):
        """Test conversion of multi-label hostname."""
        logical = hostname_to_logical("endpoint.service.api")
        assert logical == "/api/service/endpoint"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
