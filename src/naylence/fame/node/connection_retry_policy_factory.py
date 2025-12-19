"""
Connection retry policy factory for creating retry policy instances.

This module provides the factory base class and configuration types
for creating ConnectionRetryPolicy instances.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource
from naylence.fame.node.connection_retry_policy import ConnectionRetryPolicy


class ConnectionRetryPolicyConfig(ResourceConfig):
    """Configuration for connection retry policies."""

    type: str = "ConnectionRetryPolicy"

    max_initial_attempts: Optional[int] = None
    """Maximum number of connection attempts before giving up.
    - 1 (default): Fail immediately on first error
    - 0: Unlimited retries with exponential backoff
    - N > 1: Retry up to N times with exponential backoff
    """


C = TypeVar("C", bound=ConnectionRetryPolicyConfig)


class ConnectionRetryPolicyFactory(ResourceFactory[ConnectionRetryPolicy, C]):
    """Abstract factory for creating connection retry policy instances."""

    @classmethod
    async def create_connection_retry_policy(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Optional[ConnectionRetryPolicy]:
        """Create a connection retry policy instance based on the provided configuration.

        Args:
            cfg: Configuration for the policy, or None for default

        Returns:
            A ConnectionRetryPolicy instance, or None if creation fails
        """
        return await create_resource(
            ConnectionRetryPolicyFactory,
            cfg,
            **kwargs,
        )
