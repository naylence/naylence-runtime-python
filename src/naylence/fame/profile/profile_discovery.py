"""
Profile discovery from entry points.

This module provides a unified mechanism for discovering and loading profile
registrations from external packages using the 'naylence.profiles' entry point group.

Entry points should be registered with the format '<base_type>:<profile_name>' as
the entry point name, where:
- base_type is the factory base type (e.g., 'SecurityManagerFactory', 'Authorizer')
- profile_name is the profile name (e.g., 'strict-overlay', 'custom-jwt')

Example pyproject.toml entry:
    [project.entry-points."naylence.profiles"]
    "SecurityManagerFactory:strict-overlay" = "pkg.module:register_strict_overlay"
    "Authorizer:custom-jwt" = "pkg.module:register_custom_jwt"
"""

from __future__ import annotations

import importlib.metadata
from typing import Callable

from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

# Track which profiles we've already attempted to discover
_discovered: set[tuple[str, str]] = set()


def discover_profile(base_type: str, profile_name: str) -> bool:
    """Discover and register a profile from entry points.

    Searches the 'naylence.profiles' entry point group for an entry with name
    '<base_type>:<profile_name>'. If found, loads and calls the registration function.

    Args:
        base_type: The factory base type (e.g., 'SecurityManagerFactory')
        profile_name: The profile name (e.g., 'strict-overlay')

    Returns:
        True if a matching entry point was found and loaded successfully.
        False if no matching entry point exists or discovery was already attempted.

    Note:
        This function is idempotent - it will only attempt discovery once per
        base_type/profile_name combination.
    """
    key = (base_type, profile_name)
    if key in _discovered:
        return False
    _discovered.add(key)

    entry_point_name = f"{base_type}:{profile_name}"

    try:
        eps = importlib.metadata.entry_points(group="naylence.profiles")
        for ep in eps:
            if ep.name == entry_point_name:
                try:
                    register_fn: Callable[[], None] = ep.load()
                    register_fn()
                    logger.debug(
                        "discovered_profile_from_entry_point",
                        base_type=base_type,
                        profile=profile_name,
                        entry_point=ep.value,
                    )
                    return True
                except Exception as e:
                    logger.warning(
                        "failed_to_load_profile_entry_point",
                        base_type=base_type,
                        profile=profile_name,
                        entry_point=ep.value,
                        error=str(e),
                    )
                    return False
    except Exception as e:
        logger.debug(
            "profile_entry_point_discovery_failed",
            base_type=base_type,
            profile=profile_name,
            error=str(e),
        )

    return False
