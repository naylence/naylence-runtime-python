"""
Abstract factory base class for creating authorization policies.

Implementations of this factory create specific types of authorization
policies (e.g., expression-based, rule-based, etc.).
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import ConfigDict

from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
    create_resource,
)
from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)

# Base type identifier for authorization policy factories
AUTHORIZATION_POLICY_FACTORY_BASE_TYPE = "AuthorizationPolicyFactory"


class AuthorizationPolicyConfig(ResourceConfig):
    """Configuration for creating an authorization policy."""

    model_config = ConfigDict(extra="allow")

    type: str


C = TypeVar("C", bound=AuthorizationPolicyConfig)


class AuthorizationPolicyFactory(ResourceFactory[AuthorizationPolicy, C]):
    """
    Abstract factory base class for creating authorization policies.

    Implementations of this factory create specific types of authorization
    policies (e.g., expression-based, rule-based, etc.).
    """

    @classmethod
    async def create_authorization_policy(
        cls,
        config: Optional[AuthorizationPolicyConfig | dict[str, Any]] = None,
    ) -> AuthorizationPolicy | None:
        """
        Static helper to create an authorization policy using the factory registry.

        Args:
            config: Configuration for the policy

        Returns:
            The created policy, or None if no factory matched

        Raises:
            ValueError: If config is provided but policy creation fails
        """
        if config:
            policy = await create_resource(AuthorizationPolicyFactory, config)

            if not policy:
                raise ValueError(
                    "Failed to create authorization policy from configuration"
                )

            return policy

        # Try to get default factory
        policy = await create_default_resource(AuthorizationPolicyFactory)

        return policy

