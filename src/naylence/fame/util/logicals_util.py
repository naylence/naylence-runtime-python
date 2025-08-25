"""
Logical utilities for DNS-compatible certificate name constraints.

This module provides utilities for converting logicals to DNS host notation
and validating logical syntax to ensure compatibility with X.509 certificate
name constraints and OpenSSL validation.

Environment Variables:
    FAME_ROOT: Root domain for Fame logical addresses (default: "fame.fabric")
               Used for root logicals like "/" -> "fame.fabric"
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

_POOL_WILDCARD = "*"


# Get the Fame root domain from environment, default to "fame.fabric"
def get_fame_root() -> str:
    """Get the Fame root domain from FAME_ROOT environment variable."""
    return os.environ.get("FAME_ROOT", "fame.fabric")


# DNS hostname validation per RFC 1035 and RFC 5280
# - Must start with alphanumeric
# - Can contain alphanumeric, hyphens, dots
# - Must end with alphanumeric
# - Each label (segment between dots) must be 1-63 octets (RFC 1035 §2.3.4)
# - Total length must be ≤ 253 visible characters (RFC 1035 §2.3.4: 255 on wire - 2 bytes)
DNS_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"  # Total length <= 253 visible characters
    r"(?:"  # Start of each label
    r"[a-zA-Z0-9]"  # Must start with alphanumeric
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"  # Optional middle chars, must end with alphanumeric
    r"\.?"  # Optional trailing dot
    r")+$"  # End of each label
)

# DNS label validation (individual segment between dots/slashes)
DNS_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def validate_logical_segment(segment: str) -> tuple[bool, Optional[str]]:
    """
    Validate a single logical segment for DNS hostname compatibility.

    Args:
        segment: A single path segment (without leading/trailing slashes)

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if segment is DNS-compatible
        - error_message: None if valid, error description if invalid
    """
    if not segment:
        return False, "Empty path segment"

    if len(segment) > 63:
        return (
            False,
            f"Path segment '{segment}' exceeds 63 octets (RFC 1035 §2.3.4 label limit)",
        )

    # Check for invalid characters (must be alphanumeric or hyphen only)
    if not all(c.isalnum() or c == "-" for c in segment):
        return False, (
            f"Path segment '{segment}' contains invalid characters. "
            f"Must contain only alphanumeric characters and hyphens"
        )

    # Cannot start or end with hyphen
    if segment.startswith("-") or segment.endswith("-"):
        return False, f"Path segment '{segment}' cannot start or end with hyphen"

    # Cannot have consecutive hyphens (not allowed in DNS)
    if "--" in segment:
        return False, f"Path segment '{segment}' cannot contain consecutive hyphens"

    return True, None


def validate_logical(logical: str) -> tuple[bool, Optional[str]]:
    """
    Validate a complete logical for DNS hostname compatibility.

    Args:
        logical: Full logical (e.g., "/p1/p2/p3")

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if path can be converted to valid DNS hostname
        - error_message: None if valid, error description if invalid
    """
    if not logical:
        return False, "Empty logical"

    if not logical.startswith("/"):
        return False, f"Logical '{logical}' must start with '/'"

    # Split path into segments, removing empty segments
    segments = [seg for seg in logical.split("/") if seg]

    # Special case: root path "/" is valid and represents the root namespace
    if not segments and logical == "/":
        return True, None

    if not segments:
        return False, "Logical must contain at least one non-empty segment"

    # Validate each segment
    for segment in segments:
        is_valid, error = validate_logical_segment(segment)
        if not is_valid:
            return False, f"Invalid logical '{logical}': {error}"

    # Check total length when converted to hostname
    hostname = logical_to_hostname(logical)
    if len(hostname) > 253:
        return (
            False,
            f"Logical '{logical}' converts to hostname exceeding 253 characters (RFC 1035 §2.3.4 limit)",
        )

    return True, None


def logical_to_hostname(logical: str) -> str:
    """
    Convert a logical to DNS hostname notation.

    Converts "/p1/p2/p3" to "p3.p2.p1" for use in certificate name constraints.
    This allows OpenSSL to properly validate name constraints on the host part.

    Special handling for root paths:
    - "/" converts to the value of FAME_ROOT (default: "fame.fabric")
    - This allows root logical addresses like "alice@/" to work properly

    Args:
        logical: Path in format "/p1/p2/p3" or "/" for root

    Returns:
        DNS hostname in format "p3.p2.p1" or FAME_ROOT for root path

    Raises:
        ValueError: If path format is invalid
    """
    if not logical:
        raise ValueError("Empty logical")

    if not logical.startswith("/"):
        raise ValueError(f"Logical '{logical} cannot start with '/'")

    # Split path into segments, removing empty segments
    segments = [seg for seg in logical.split("/") if seg]

    # Special case: root path "/" converts to FAME_ROOT
    if not segments and logical == "/":
        return get_fame_root()

    if not segments:
        raise ValueError("Logical must contain at least one non-empty segment")

    # Reverse segments and join with dots
    return ".".join(reversed(segments))


def hostname_to_logical(hostname: str) -> str:
    """
    Convert a DNS hostname back to logical notation.

    Converts "p3.p2.p1" back to "/p1/p2/p3".

    Special handling for root domain:
    - FAME_ROOT hostname converts back to "/"

    Args:
        hostname: DNS hostname in format "p3.p2.p1" or FAME_ROOT

    Returns:
        Logical in format "/p1/p2/p3" or "/" for root domain

    Raises:
        ValueError: If hostname format is invalid
    """
    if not hostname:
        raise ValueError("Empty hostname")

    # Special case: FAME_ROOT hostname converts back to "/"
    if hostname == get_fame_root():
        return "/"

    # Split by dots and reverse
    segments = hostname.split(".")

    if not segments or any(not seg for seg in segments):
        raise ValueError(f"Invalid hostname '{hostname}' contains empty segments")

    # Reverse segments and join with slashes
    return "/" + "/".join(reversed(segments))


def logicals_to_hostnames(logicals: List[str]) -> List[str]:
    """
    Convert a list of logicals to DNS hostnames.

    Args:
        logicals: List of paths in format ["/p1/p2", "/q1/q2/q3"]

    Returns:
        List of hostnames in format ["p2.p1", "q3.q2.q1"]

    Raises:
        ValueError: If any path format is invalid
    """
    return [logical_to_hostname(path) for path in logicals]


def hostnames_to_logicals(hostnames: List[str]) -> List[str]:
    """
    Convert a list of DNS hostnames back to logicals.

    Args:
        hostnames: List of hostnames in format ["p2.p1", "q3.q2.q1"]

    Returns:
        List of paths in format ["/p1/p2", "/q1/q2/q3"]

    Raises:
        ValueError: If any hostname format is invalid
    """
    return [hostname_to_logical(hostname) for hostname in hostnames]


def create_logical_uri(logical: str, use_hostname_notation: bool = False) -> str:
    """
    Create a URI for use in X.509 certificates.

    Args:
        logical: Logical (e.g., "/p1/p2/p3")
        use_hostname_notation: If True, convert to hostname notation for name constraints

    Returns:
        URI string for certificate SAN extension

    Examples:
        create_logical_uri("/p1/p2/p3", False) -> "naylence:///p1/p2/p3"
        create_logical_uri("/p1/p2/p3", True) -> "naylence://p3.p2.p1/"
    """
    if use_hostname_notation:
        hostname = logical_to_hostname(logical)
        return f"naylence://{hostname}/"
    else:
        return f"naylence://{logical}"


def extract_logical_from_uri(uri: str) -> Optional[str]:
    """
    Extract logical from a naylence:// URI.

    Args:
        uri: URI from certificate (e.g., "naylence://p3.p2.p1/" or "naylence:///p1/p2/p3")

    Returns:
        Logical in standard format "/p1/p2/p3", or None if not a valid naylence URI
    """
    if not uri.startswith("naylence://"):
        return None

    # Remove naylence:// prefix
    remainder = uri[11:]  # len('naylence://') == 11

    if remainder.startswith("/"):
        # Path notation: naylence:///p1/p2/p3
        return remainder
    elif remainder.endswith("/"):
        # Hostname notation: naylence://p3.p2.p1/
        hostname = remainder[:-1]  # Remove trailing slash
        try:
            return hostname_to_logical(hostname)
        except ValueError:
            return None
    else:
        # Could be hostname without trailing slash
        try:
            return hostname_to_logical(remainder)
        except ValueError:
            # Could be path without leading slash
            if remainder and "." not in remainder:
                return f"/{remainder}"
            return None


def extract_host_logical_from_uri(uri: str) -> Optional[str]:
    """
    Extract host-like logical address from a naylence:// URI.

    Args:
        uri: URI from certificate (e.g., "naylence://fame.fabric/" or "naylence:///")

    Returns:
        Host-like logical address (e.g., "fame.fabric"), or None if not a valid naylence URI
    """
    if not uri.startswith("naylence://"):
        return None

    # Remove naylence:// prefix
    remainder = uri[11:]  # len('naylence://') == 11

    if remainder.startswith("/"):
        # Path notation: naylence:///p1/p2/p3 -> convert to host-like
        path = remainder
        try:
            return logical_to_hostname(path)
        except ValueError:
            return None
    elif remainder.endswith("/"):
        # Hostname notation: naylence://fame.fabric/
        hostname = remainder[:-1]  # Remove trailing slash
        return hostname if hostname else None
    else:
        # Hostname without trailing slash: naylence://fame.fabric
        return remainder if remainder else None


def validate_host_logical(host_logical: str) -> tuple[bool, Optional[str]]:
    """
    Validate a host-like logical address for DNS hostname compatibility.

    Supports wildcards (*) in the leftmost position only, consistent with
    the FAME host-only wildcard restriction.

    Args:
        host_logical: Host-like logical address (e.g., "api.services", "*.fame.fabric")

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if host logical is DNS-compatible
        - error_message: None if valid, error description if invalid
    """
    if not host_logical:
        return False, "Empty host logical"

    # Check for wildcard patterns
    if "*" in host_logical:
        # Wildcards are only allowed in leftmost position
        if not host_logical.startswith("*."):
            return (
                False,
                f"Host logical '{host_logical}' contains wildcard not in leftmost position. "
                f"Only '*.domain' patterns are allowed",
            )

        # Extract the base domain (everything after '*.')
        base_domain = host_logical[2:]  # Remove '*.'

        if not base_domain:
            return (
                False,
                f"Host logical '{host_logical}' has wildcard but no base domain",
            )

        # Validate the base domain part using standard DNS rules
        if not DNS_HOSTNAME_PATTERN.match(base_domain):
            return (
                False,
                f"Host logical '{host_logical}' base domain '{base_domain}' is not a valid DNS hostname",
            )

        # Check total length (including the '*.')
        if len(host_logical) > 253:
            return (
                False,
                f"Host logical '{host_logical}' exceeds 253 characters (RFC 1035 §2.3.4 limit)",
            )

        # Validate each label in the base domain
        labels = base_domain.split(".")
        for label in labels:
            if not DNS_LABEL_PATTERN.match(label):
                return (
                    False,
                    f"Host logical '{host_logical}' contains invalid label '{label}' in base domain",
                )

        return True, None

    # For non-wildcard hosts, use standard DNS validation
    # Check overall hostname format
    if not DNS_HOSTNAME_PATTERN.match(host_logical):
        return False, f"Host logical '{host_logical}' is not a valid DNS hostname"

    # Check total length
    if len(host_logical) > 253:
        return (
            False,
            f"Host logical '{host_logical}' exceeds 253 characters (RFC 1035 §2.3.4 limit)",
        )

    # Validate each label (segment between dots)
    labels = host_logical.split(".")
    for label in labels:
        if not DNS_LABEL_PATTERN.match(label):
            return (
                False,
                f"Host logical '{host_logical}' contains invalid label '{label}'",
            )

    return True, None


def validate_host_logicals(host_logicals: List[str]) -> tuple[bool, Optional[str]]:
    """
    Validate a list of host-like logical addresses for DNS hostname compatibility.

    Args:
        host_logicals: List of host-like logical addresses to validate

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if all host logicals are valid
        - error_message: None if valid, description of first error found
    """
    if not host_logicals:
        return True, None  # Empty list is valid

    for host_logical in host_logicals:
        is_valid, error = validate_host_logical(host_logical)
        if not is_valid:
            return False, error

    return True, None


def create_host_logical_uri(host_logical: str) -> str:
    """
    Create a URI for host-like logical addresses for use in X.509 certificates.

    Args:
        host_logical: Host-like logical address (e.g., "api.services", "fame.fabric")

    Returns:
        URI string for certificate SAN extension

    Examples:
        create_host_logical_uri("api.services") -> "naylence://api.services/"
        create_host_logical_uri("fame.fabric") -> "naylence://fame.fabric/"
    """
    return f"naylence://{host_logical}/"


def convert_wildcard_logical_to_dns_constraint(logical_pattern: str) -> str:
    """
    Convert a wildcard logical pattern to a proper DNS name constraint.

    For X.509 name constraints, wildcard patterns like "*.fame.fabric" should be
    represented as ".fame.fabric" (starting with dot) to match all subdomains.

    Args:
        logical_pattern: Logical pattern like "*.fame.fabric"

    Returns:
        DNS constraint string like ".fame.fabric"

    Examples:
        convert_wildcard_logical_to_dns_constraint("*.fame.fabric") -> ".fame.fabric"
        convert_wildcard_logical_to_dns_constraint("fame.fabric") -> "fame.fabric"
    """
    if logical_pattern.startswith("*."):
        return logical_pattern[1:]  # Remove "*" to get ".fame.fabric"
    return logical_pattern


def logical_patterns_to_dns_constraints(logical_patterns: List[str]) -> List[str]:
    """
    Convert a list of logical patterns to DNS name constraints.

    Handles both regular logical addresses and wildcard patterns, converting
    wildcards to proper DNS constraint format for X.509 certificates.

    Args:
        logical_patterns: List of logical patterns, may include wildcards

    Returns:
        List of DNS constraint strings suitable for X.509 name constraints

    Examples:
        logical_patterns_to_dns_constraints(["api.services", "*.fame.fabric"])
        -> ["api.services", ".fame.fabric"]
    """
    constraints = []
    for pattern in logical_patterns:
        constraint = convert_wildcard_logical_to_dns_constraint(pattern)
        constraints.append(constraint)
    return constraints


def is_pool_logical(logical: str) -> bool:
    """Check if a logical is a pool definition (contains wildcard)."""
    return logical.startswith(_POOL_WILDCARD + ".")


def matches_pool_logical(logical: str, pool_pattern: str) -> bool:
    """
    Check if a logical matches a pool pattern.

    Args:
        logical: Exact logical (e.g., "api.service.domain" or "service.domain")
        pool_pattern: Pool pattern (e.g., "*.service.domain")

    Returns:
        True if the logical matches the pool pattern
    """
    if not is_pool_logical(pool_pattern):
        return False

    # Remove the wildcard and check if the rest matches
    pool_suffix = pool_pattern[2:]  # Remove "*."

    # Allow both subdomain matching and base domain matching
    # e.g., both "api.service.domain" and "service.domain" match "*.service.domain"
    return (logical.endswith("." + pool_suffix) and logical != pool_suffix) or logical == pool_suffix


def matches_pool_address(address: str, pool_address: str) -> bool:
    """
    Check if an address matches a pool address pattern.

    Args:
        address: Full address (e.g., "math@node1.fame.fabric" or "math@fame.fabric")
        pool_address: Pool address pattern (e.g., "math@*.fame.fabric")

    Returns:
        True if the address matches the pool pattern
    """
    from naylence.fame.core import parse_address_components

    try:
        addr_participant, addr_host, addr_path = parse_address_components(address)
        pool_participant, pool_host, pool_path = parse_address_components(pool_address)

        # Participants must match
        if addr_participant != pool_participant:
            return False

        # Compare based on what parts are present
        if addr_host is not None and pool_host is not None:
            # Both have hosts: check host matching with wildcards
            host_matches = matches_pool_logical(addr_host, pool_host)
            if not host_matches:
                return False

            # If both have paths, they must match exactly (no wildcards in paths)
            if addr_path is not None and pool_path is not None:
                return addr_path == pool_path
            elif addr_path is None and pool_path is None:
                return True  # Both host-only and host matches
            else:
                return False  # One has path, other doesn't

        elif addr_path is not None and pool_path is not None and addr_host is None and pool_host is None:
            # Both are path-only: exact match only (no wildcards in paths)
            return addr_path == pool_path

        else:
            # Mismatch in address format (host vs path)
            return False
    except Exception as e:
        # Debug: print the exception
        print(f"Exception in matches_pool_address: {e}")
        return False


def extract_pool_base(pool_pattern: str) -> Optional[str]:
    """
    Extract the base part from a pool pattern.

    Args:
        pool_pattern: Pool pattern like "*.service.domain"

    Returns:
        Base part like "service.domain" or None if not a pool pattern
    """
    if not is_pool_logical(pool_pattern):
        return None
    return pool_pattern[2:]  # Remove "*."


def extract_pool_address_base(pool_address: str) -> Optional[str]:
    """
    Extract the base address from a pool address pattern.

    Args:
        pool_address: Pool address like "math@*.fame.fabric"

    Returns:
        Base address like "math@fame.fabric" or None if not a pool pattern
    """
    from naylence.fame.core import parse_address_components

    try:
        participant, host, path = parse_address_components(pool_address)

        # Only support host-based pool patterns (wildcards only in host part)
        if host and is_pool_logical(host):
            base_host = extract_pool_base(host)
            if base_host:
                if path:
                    return f"{participant}@{base_host}{path}"
                else:
                    return f"{participant}@{base_host}"

        return None
    except Exception:
        return None


def is_pool_address(address: str) -> bool:
    """Check if an address is a pool pattern (contains wildcards in host part only)."""
    from naylence.fame.core import parse_address_components

    try:
        participant, host, path = parse_address_components(address)

        # Only host-based wildcards are supported
        if host and is_pool_logical(host):
            return True

        return False
    except Exception:
        return False
