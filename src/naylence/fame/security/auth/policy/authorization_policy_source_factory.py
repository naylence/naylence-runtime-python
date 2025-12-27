"""
Abstract factory base class for creating authorization policy sources.

Implementations of this factory create specific types of policy sources
(e.g., local file, remote store, in-memory, etc.).
"""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import ConfigDict

from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
    create_resource,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)

# Base type identifier for authorization policy source factories
AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE = "AuthorizationPolicySourceFactory"


class AuthorizationPolicySourceConfig(ResourceConfig):
    """Configuration for creating an authorization policy source."""

    model_config = ConfigDict(extra="allow")

    type: str


C = TypeVar("C", bound=AuthorizationPolicySourceConfig)


class AuthorizationPolicySourceFactory(ResourceFactory[AuthorizationPolicySource, C]):
    """
    Abstract factory base class for creating authorization policy sources.

    Implementations of this factory create specific types of policy sources
    (e.g., local file, remote store, in-memory, etc.).
    """

    @classmethod
    async def create_authorization_policy_source(
        cls,
        config: AuthorizationPolicySourceConfig | dict[str, Any] | None = None,
    ) -> AuthorizationPolicySource | None:
        """
        Static helper to create an authorization policy source using the registry.

        Args:
            config: Configuration for the policy source

        Returns:
            The created policy source, or None if no factory matched

        Raises:
            ValueError: If config is provided but source creation fails
        """
        if config:
            source = await create_resource(
                AuthorizationPolicySourceFactory,
                config,
            )

            if not source:
                raise ValueError(
                    "Failed to create authorization policy source from configuration"
                )

            return source

        # Try to get default factory
        source = await create_default_resource(AuthorizationPolicySourceFactory)

        return source
