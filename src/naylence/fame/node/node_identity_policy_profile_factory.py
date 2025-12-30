"""
Node identity policy profile factory.

This module provides a factory that creates NodeIdentityPolicy instances
based on named profiles, allowing simple configuration of common policies.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.node.node_identity_policy import NodeIdentityPolicy
from naylence.fame.node.node_identity_policy_factory import (
    NodeIdentityPolicyConfig,
    NodeIdentityPolicyFactory,
)
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


# Profile name constants
PROFILE_NAME_DEFAULT = "default"
PROFILE_NAME_TOKEN_SUBJECT = "token-subject"
PROFILE_NAME_TOKEN_SUBJECT_ALIAS = "token_subject"

# Profile configurations
DEFAULT_PROFILE: dict[str, Any] = {"type": "DefaultNodeIdentityPolicy"}
TOKEN_SUBJECT_PROFILE: dict[str, Any] = {"type": "TokenSubjectNodeIdentityPolicy"}

# Node identity policy factory base type constant
NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE = "NodeIdentityPolicyFactory"

# Register built-in profiles
_profiles_registered = False

def _ensure_profiles_registered() -> None:
    """Ensure built-in node identity policy profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="node-identity-policy-profile-factory")
    register_profile(NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_DEFAULT, DEFAULT_PROFILE, opts)
    register_profile(NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_TOKEN_SUBJECT, TOKEN_SUBJECT_PROFILE, opts)
    register_profile(NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE, PROFILE_NAME_TOKEN_SUBJECT_ALIAS, TOKEN_SUBJECT_PROFILE, opts)
    _profiles_registered = True

_ensure_profiles_registered()


class NodeIdentityPolicyProfileConfig(NodeIdentityPolicyConfig):
    """Configuration for the profile-based node identity policy factory."""

    type: str = "NodeIdentityPolicyProfile"
    profile: Optional[str] = None


class NodeIdentityPolicyProfileFactory(NodeIdentityPolicyFactory):
    """
    Factory that creates NodeIdentityPolicy instances based on named profiles.

    Supported profiles:
    - "default": Uses DefaultNodeIdentityPolicy
    - "token-subject" or "token_subject": Uses TokenSubjectNodeIdentityPolicy
    """

    async def create(
        self,
        config: Optional[NodeIdentityPolicyProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> NodeIdentityPolicy:
        """Create a NodeIdentityPolicy instance based on the configured profile.

        Args:
            config: Configuration containing the profile name

        Returns:
            A NodeIdentityPolicy instance matching the profile
        """
        normalized = self._normalize_config(config)
        profile_config = self._resolve_profile_config(normalized.profile or PROFILE_NAME_DEFAULT)

        logger.debug(
            "enabling_node_identity_policy_profile",
            profile=normalized.profile,
        )

        result = await NodeIdentityPolicyFactory.create_node_identity_policy(profile_config)
        if result is None:
            raise RuntimeError(f"Failed to create node identity policy for profile: {normalized.profile}")
        return result

    def _normalize_config(
        self,
        config: Optional[NodeIdentityPolicyProfileConfig | dict[str, Any]],
    ) -> NodeIdentityPolicyProfileConfig:
        """Normalize configuration to NodeIdentityPolicyProfileConfig."""
        if config is None:
            return NodeIdentityPolicyProfileConfig()

        if isinstance(config, dict):
            return NodeIdentityPolicyProfileConfig(**config)

        return config

    def _resolve_profile_config(self, profile_name: str) -> NodeIdentityPolicyConfig:
        """Resolve a profile name to its corresponding configuration."""
        _ensure_profiles_registered()
        normalized_name = profile_name.lower().strip()

        profile = get_profile(NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE, normalized_name)
        if profile is not None:
            return NodeIdentityPolicyConfig(**profile)

        # Try to discover from entry points
        discover_profile(NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE, normalized_name)

        profile = get_profile(NODE_IDENTITY_POLICY_FACTORY_BASE_TYPE, normalized_name)
        if profile is not None:
            return NodeIdentityPolicyConfig(**profile)

        logger.warning(
            "unknown_identity_policy_profile",
            profile=profile_name,
            falling_back_to="default",
        )
        return NodeIdentityPolicyConfig(**DEFAULT_PROFILE)
