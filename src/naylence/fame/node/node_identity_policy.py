"""
Node identity policy protocol and context models.

This module defines the protocol for node identity resolution strategies
and the context models used during identity resolution phases.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.security.auth.auth_identity import AuthIdentity


class InitialIdentityContext(BaseModel):
    """
    Context for initial node ID resolution.

    This context is used during node initialization, before any admission attempts,
    to determine the initial node ID based on configuration and persisted state.
    """

    configured_id: Optional[str] = Field(
        default=None,
        description="The node ID explicitly configured by the user",
    )
    persisted_id: Optional[str] = Field(
        default=None,
        description="The node ID persisted from a previous session",
    )

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )


class NodeIdentityPolicyContext(BaseModel):
    """
    Context for admission-phase node ID resolution.

    This context is used during the admission phase to optionally adjust
    the node ID based on authentication information from grants.
    """

    current_node_id: str = Field(
        ...,
        description="The node ID determined so far (configured, persisted, or generated)",
    )
    identities: List[AuthIdentity] = Field(
        default_factory=list,
        description="List of authenticated identities available",
    )
    grants: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Connection grants that may contain authentication information",
    )

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )


@runtime_checkable
class NodeIdentityPolicy(Protocol):
    """
    Protocol for node identity resolution strategies.

    Node identity policies determine how node IDs are resolved at different
    phases of the node lifecycle:
    - Initial: During node startup, before admission
    - Admission: When connecting to upstream, potentially adjusting ID based on auth
    """

    async def resolve_initial_node_id(self, context: InitialIdentityContext) -> str:
        """
        Determine the initial node ID for the node.

        This method is called during node initialization, before any admission attempts.
        It should return a stable node ID based on configuration and persisted state.

        Args:
            context: The initial identity context with configured and persisted IDs

        Returns:
            The resolved initial node ID
        """
        ...

    async def resolve_admission_node_id(self, context: NodeIdentityPolicyContext) -> str:
        """
        Optionally adjust the node ID based on admission context.

        This method is called during the admission phase and can adjust the node ID
        based on authentication information from connection grants.

        Args:
            context: The admission context with current node ID, identities, and grants

        Returns:
            The final node ID to use (may be the same as current_node_id or adjusted)
        """
        ...
