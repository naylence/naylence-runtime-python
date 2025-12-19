"""
Node identity policy factory for creating policy instances.

This module provides the factory base class and configuration types
for creating NodeIdentityPolicy instances.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import ConfigDict
from pydantic.alias_generators import to_camel

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource
from naylence.fame.node.node_identity_policy import NodeIdentityPolicy


class NodeIdentityPolicyConfig(ResourceConfig):
    """Base configuration for node identity policies."""

    type: str = "NodeIdentityPolicy"

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
    )


C = TypeVar("C", bound=NodeIdentityPolicyConfig)


class NodeIdentityPolicyFactory(ResourceFactory[NodeIdentityPolicy, C]):
    """Abstract factory for creating node identity policy instances."""

    @classmethod
    async def create_node_identity_policy(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Optional[NodeIdentityPolicy]:
        """Create a node identity policy instance based on the provided configuration.

        Args:
            cfg: Configuration for the policy, or None for default

        Returns:
            A NodeIdentityPolicy instance, or None if creation fails
        """
        return await create_resource(
            NodeIdentityPolicyFactory,
            cfg,
            **kwargs,
        )
