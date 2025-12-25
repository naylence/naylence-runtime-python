"""
Default node identity policy implementation.

This module provides the default implementation of NodeIdentityPolicy
that preserves the current node ID without deriving identity from tokens.

For token-subject-based identity, use TokenSubjectNodeIdentityPolicy.
"""

from __future__ import annotations

from naylence.fame.core import generate_id
from naylence.fame.node.node_identity_policy import (
    InitialIdentityContext,
    NodeIdentityPolicy,
    NodeIdentityPolicyContext,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultNodeIdentityPolicy(NodeIdentityPolicy):
    """
    Default implementation of NodeIdentityPolicy.

    This policy does NOT derive identity from tokens or grants.
    For token-subject-based identity, use TokenSubjectNodeIdentityPolicy.

    Initial ID resolution priority:
    1. Configured ID (explicitly set by user)
    2. Persisted ID (from previous session)
    3. Generated fingerprint-based ID

    Admission ID resolution:
    - Returns current node ID if present
    - Otherwise generates a new fingerprint-based ID
    """

    async def resolve_initial_node_id(self, context: InitialIdentityContext) -> str:
        """
        Resolve initial node ID with priority: configured > persisted > generated.

        Args:
            context: The initial identity context

        Returns:
            The resolved node ID
        """
        if context.configured_id:
            logger.debug(
                "using_configured_node_id",
                node_id=context.configured_id,
            )
            return context.configured_id

        if context.persisted_id:
            logger.debug(
                "using_persisted_node_id",
                node_id=context.persisted_id,
            )
            return context.persisted_id

        generated_id = generate_id(mode="fingerprint")
        logger.debug(
            "generated_fingerprint_node_id",
            node_id=generated_id,
        )
        return generated_id

    async def resolve_admission_node_id(self, context: NodeIdentityPolicyContext) -> str:
        """
        Resolve admission node ID by preserving current ID or generating a new one.

        Args:
            context: The admission context

        Returns:
            The current node ID if present, otherwise a generated fingerprint ID
        """
        if context.current_node_id:
            return context.current_node_id
        return generate_id(mode="fingerprint")


# Type assertion for protocol compliance
_: NodeIdentityPolicy = DefaultNodeIdentityPolicy()
