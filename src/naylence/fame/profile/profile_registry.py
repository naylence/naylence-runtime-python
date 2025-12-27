"""
Profile registry for managing factory configuration profiles.

This module provides a registry for factory profiles, allowing factories
to register named configuration templates that can be retrieved and used
at runtime.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Optional

# Type alias for profile configuration
ProfileConfig = dict[str, Any]


@dataclass
class RegisterProfileOptions:
    """Options for registering a profile."""

    allow_override: bool = False
    source: Optional[str] = None


# Internal registry: base_type -> profile_name -> config
_registry: dict[str, dict[str, ProfileConfig]] = {}


def _normalize_key(value: str, label: str) -> str:
    """Normalize and validate a registry key."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a non-empty string")

    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{label} must be a non-empty string")

    return trimmed


def _clone_config(config: ProfileConfig) -> ProfileConfig:
    """Deep clone a profile configuration."""
    return copy.deepcopy(config)


def register_profile(
    base_type: str,
    name: str,
    config: ProfileConfig,
    options: Optional[RegisterProfileOptions] = None,
) -> None:
    """
    Register a profile configuration for a factory type.

    Args:
        base_type: The factory base type (e.g., 'Authorizer')
        name: The profile name (e.g., 'oauth2', 'noop')
        config: The configuration dictionary for the profile
        options: Optional registration options

    Raises:
        ValueError: If base_type or name are empty
        ValueError: If config is not a dictionary
        ValueError: If profile already exists and allow_override is False
    """
    opts = options or RegisterProfileOptions()
    normalized_base = _normalize_key(base_type, "baseType")
    normalized_name = _normalize_key(name, "profile name")

    if config is None or not isinstance(config, dict):
        raise ValueError(f"Profile '{normalized_name}' config must be an object")

    profiles = _registry.get(normalized_base)
    if profiles is None:
        profiles = {}
        _registry[normalized_base] = profiles

    if normalized_name in profiles and not opts.allow_override:
        source_label = f" ({opts.source})" if opts.source else ""
        raise ValueError(
            f"Profile '{normalized_name}' already registered for "
            f"{normalized_base}{source_label}"
        )

    profiles[normalized_name] = config


def get_profile(base_type: str, name: str) -> Optional[ProfileConfig]:
    """
    Retrieve a profile configuration by type and name.

    Args:
        base_type: The factory base type
        name: The profile name

    Returns:
        A deep copy of the profile configuration, or None if not found
    """
    normalized_base = _normalize_key(base_type, "baseType")
    normalized_name = _normalize_key(name, "profile name")

    profiles = _registry.get(normalized_base)
    if profiles is None:
        return None

    profile = profiles.get(normalized_name)
    return _clone_config(profile) if profile else None


def list_profiles(base_type: str) -> list[str]:
    """
    List all profile names registered for a factory type.

    Args:
        base_type: The factory base type

    Returns:
        List of profile names
    """
    normalized_base = _normalize_key(base_type, "baseType")
    profiles = _registry.get(normalized_base)
    return list(profiles.keys()) if profiles else []


def clear_profiles(base_type: Optional[str] = None) -> None:
    """
    Clear registered profiles.

    Args:
        base_type: If provided, clear only profiles for this type.
                   If None, clear all profiles.
    """
    global _registry

    if base_type is None:
        _registry.clear()
        return

    normalized_base = _normalize_key(base_type, "baseType")
    if normalized_base in _registry:
        del _registry[normalized_base]
