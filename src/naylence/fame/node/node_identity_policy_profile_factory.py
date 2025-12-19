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
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


# Profile name constants
PROFILE_NAME_DEFAULT = "default"
PROFILE_NAME_TOKEN_SUBJECT = "token-subject"
PROFILE_NAME_TOKEN_SUBJECT_ALIAS = "token_subject"

# Profile configurations
DEFAULT_PROFILE: NodeIdentityPolicyConfig = NodeIdentityPolicyConfig(type="DefaultNodeIdentityPolicy")
TOKEN_SUBJECT_PROFILE: NodeIdentityPolicyConfig = NodeIdentityPolicyConfig(
    type="TokenSubjectNodeIdentityPolicy"
)

PROFILE_MAP: dict[str, NodeIdentityPolicyConfig] = {
    PROFILE_NAME_DEFAULT: DEFAULT_PROFILE,
    PROFILE_NAME_TOKEN_SUBJECT: TOKEN_SUBJECT_PROFILE,
    PROFILE_NAME_TOKEN_SUBJECT_ALIAS: TOKEN_SUBJECT_PROFILE,
}


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
        normalized_name = profile_name.lower().strip()

        if normalized_name in PROFILE_MAP:
            # Return a copy to avoid mutation
            original = PROFILE_MAP[normalized_name]
            return NodeIdentityPolicyConfig(type=original.type)

        logger.warning(
            "unknown_identity_policy_profile",
            profile=profile_name,
            falling_back_to="default",
        )
        return NodeIdentityPolicyConfig(type=DEFAULT_PROFILE.type)
