"""
Profile registry module.

Provides a central registry for factory profiles, allowing factories
to register and retrieve configuration profiles by name.
"""

from .profile_registry import (
    ProfileConfig,
    RegisterProfileOptions,
    clear_profiles,
    get_profile,
    list_profiles,
    register_profile,
)

__all__ = [
    "ProfileConfig",
    "RegisterProfileOptions",
    "register_profile",
    "get_profile",
    "list_profiles",
    "clear_profiles",
]
