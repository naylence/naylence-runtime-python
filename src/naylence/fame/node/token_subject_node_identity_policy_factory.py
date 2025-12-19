"""
Token subject node identity policy factory.

This module provides the factory for creating TokenSubjectNodeIdentityPolicy instances.
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


class TokenSubjectNodeIdentityPolicyConfig(NodeIdentityPolicyConfig):
    """Configuration for the token subject node identity policy."""

    type: str = "TokenSubjectNodeIdentityPolicy"


class TokenSubjectNodeIdentityPolicyFactory(NodeIdentityPolicyFactory):
    """Factory for creating TokenSubjectNodeIdentityPolicy instances."""

    async def create(
        self,
        config: Optional[TokenSubjectNodeIdentityPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> NodeIdentityPolicy:
        """Create a TokenSubjectNodeIdentityPolicy instance.

        Args:
            config: Configuration for the policy (currently unused)

        Returns:
            A TokenSubjectNodeIdentityPolicy instance
        """
        from naylence.fame.node.token_subject_node_identity_policy import (
            TokenSubjectNodeIdentityPolicy,
        )

        policy = TokenSubjectNodeIdentityPolicy()
        logger.debug("token_subject_node_identity_policy_created")
        return policy
