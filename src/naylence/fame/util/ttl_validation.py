"""
TTL validation utilities for ensuring TTL values are within acceptable ranges.

This module provides validation functions to ensure TTL values are reasonable
and prevent common configuration errors that could cause security or performance issues.
"""

from typing import Optional, Union

from naylence.fame.constants.ttl_constants import (
    MAX_NODE_ATTACH_TTL_SEC,
    MAX_OAUTH2_TTL_SEC,
    TTL_NEVER_EXPIRES,
)


class TTLValidationError(ValueError):
    """Raised when TTL validation fails."""

    pass


def validate_ttl_sec(
    ttl_sec: Optional[Union[int, float]],
    min_ttl_sec: Union[int, float] = 1,
    max_ttl_sec: Optional[Union[int, float]] = None,
    allow_never_expires: bool = True,
    context: str = "TTL",
) -> Optional[Union[int, float]]:
    """
    Validate a TTL value in seconds.

    Args:
        ttl_sec: The TTL value to validate (can be None)
        min_ttl_sec: Minimum allowed TTL value (default: 1 second)
        max_ttl_sec: Maximum allowed TTL value (optional)
        allow_never_expires: Whether to allow TTL_NEVER_EXPIRES (0) value
        context: Description of what this TTL is for (used in error messages)

    Returns:
        The validated TTL value

    Raises:
        TTLValidationError: If validation fails
    """
    if ttl_sec is None:
        return None

    # Check for never expires
    if ttl_sec == TTL_NEVER_EXPIRES:
        if allow_never_expires:
            return ttl_sec
        else:
            raise TTLValidationError(f"{context} cannot be set to never expire (0)")

    # Check for negative values
    if ttl_sec < 0:
        raise TTLValidationError(f"{context} cannot be negative: {ttl_sec}")

    # Check minimum bound
    if ttl_sec < min_ttl_sec:
        raise TTLValidationError(
            f"{context} is too small: {ttl_sec} seconds (minimum: {min_ttl_sec} seconds)"
        )

    # Check maximum bound
    if max_ttl_sec is not None and ttl_sec > max_ttl_sec:
        raise TTLValidationError(
            f"{context} is too large: {ttl_sec} seconds (maximum: {max_ttl_sec} seconds)"
        )

    return ttl_sec


def validate_node_attach_ttl_sec(
    ttl_sec: Optional[Union[int, float]],
) -> Optional[Union[int, float]]:
    """Validate a node attachment TTL value."""
    return validate_ttl_sec(
        ttl_sec,
        min_ttl_sec=30,  # At least 30 seconds for node attachments
        max_ttl_sec=MAX_NODE_ATTACH_TTL_SEC,
        allow_never_expires=True,
        context="Node attachment TTL",
    )


def validate_oauth2_ttl_sec(
    ttl_sec: Optional[Union[int, float]],
) -> Optional[Union[int, float]]:
    """Validate an OAuth2 authorization TTL value."""
    return validate_ttl_sec(
        ttl_sec,
        min_ttl_sec=60,  # At least 1 minute for OAuth2 tokens
        max_ttl_sec=MAX_OAUTH2_TTL_SEC,
        allow_never_expires=False,  # OAuth2 tokens should expire
        context="OAuth2 authorization TTL",
    )


def validate_jwt_token_ttl_sec(
    ttl_sec: Optional[Union[int, float]],
) -> Optional[Union[int, float]]:
    """Validate a JWT token TTL value."""
    return validate_ttl_sec(
        ttl_sec,
        min_ttl_sec=60,  # At least 1 minute for JWT tokens
        max_ttl_sec=MAX_OAUTH2_TTL_SEC,  # Use same max as OAuth2
        allow_never_expires=False,  # JWT tokens should expire
        context="JWT token TTL",
    )


def validate_cache_ttl_sec(
    ttl_sec: Optional[Union[int, float]],
) -> Optional[Union[int, float]]:
    """Validate a cache TTL value."""
    return validate_ttl_sec(
        ttl_sec,
        min_ttl_sec=1,  # Caches can be very short-lived
        max_ttl_sec=3600,  # Max 1 hour for cache TTL
        allow_never_expires=True,  # Some caches might not expire
        context="Cache TTL",
    )


def validate_key_correlation_ttl_sec(
    ttl_sec: Optional[Union[int, float]],
) -> Optional[Union[int, float]]:
    """Validate a key correlation TTL value."""
    return validate_ttl_sec(
        ttl_sec,
        min_ttl_sec=0.1,  # Allow very short TTL for testing scenarios
        max_ttl_sec=300,  # Max 5 minutes for key correlation
        allow_never_expires=False,  # Key correlations should expire
        context="Key correlation TTL",
    )
