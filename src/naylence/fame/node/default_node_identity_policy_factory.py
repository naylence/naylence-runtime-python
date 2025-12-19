"""
Default node identity policy factory.

This module provides the factory for creating DefaultNodeIdentityPolicy instances.
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


class DefaultNodeIdentityPolicyConfig(NodeIdentityPolicyConfig):
    """Configuration for the default node identity policy."""

    type: str = "DefaultNodeIdentityPolicy"


class DefaultNodeIdentityPolicyFactory(NodeIdentityPolicyFactory):
    """Factory for creating DefaultNodeIdentityPolicy instances."""

    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultNodeIdentityPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> NodeIdentityPolicy:
        """Create a DefaultNodeIdentityPolicy instance.

        Args:
            config: Configuration for the policy (currently unused)

        Returns:
            A DefaultNodeIdentityPolicy instance
        """
        from naylence.fame.node.default_node_identity_policy import (
            DefaultNodeIdentityPolicy,
        )

        policy = DefaultNodeIdentityPolicy()
        logger.debug("default_node_identity_policy_created")
        return policy
