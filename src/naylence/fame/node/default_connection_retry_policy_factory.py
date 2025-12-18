"""
Default connection retry policy factory.

This module provides the factory for creating DefaultConnectionRetryPolicy instances.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.node.connection_retry_policy import ConnectionRetryPolicy
from naylence.fame.node.connection_retry_policy_factory import (
    ConnectionRetryPolicyConfig,
    ConnectionRetryPolicyFactory,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultConnectionRetryPolicyConfig(ConnectionRetryPolicyConfig):
    """Configuration for the default connection retry policy."""

    type: str = "DefaultConnectionRetryPolicy"


class DefaultConnectionRetryPolicyFactory(ConnectionRetryPolicyFactory):
    """Factory for creating DefaultConnectionRetryPolicy instances."""

    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultConnectionRetryPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> ConnectionRetryPolicy:
        """Create a DefaultConnectionRetryPolicy instance.

        Args:
            config: Configuration for the policy

        Returns:
            A DefaultConnectionRetryPolicy instance
        """
        from naylence.fame.node.default_connection_retry_policy import (
            DefaultConnectionRetryPolicy,
            DefaultConnectionRetryPolicyOptions,
        )

        if isinstance(config, dict):
            config = DefaultConnectionRetryPolicyConfig(**config)

        options = DefaultConnectionRetryPolicyOptions()

        if config and config.max_initial_attempts is not None:
            options.max_initial_attempts = config.max_initial_attempts

        policy = DefaultConnectionRetryPolicy(options)
        logger.debug(
            "connection_retry_policy_created",
            max_initial_attempts=policy.max_initial_attempts,
        )
        return policy
