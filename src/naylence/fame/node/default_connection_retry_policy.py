"""
Default connection retry policy implementation.

This module provides the default implementation of the ConnectionRetryPolicy
protocol that uses configurable maximum initial attempts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from naylence.fame.node.connection_retry_policy import (
    ConnectionRetryContext,
    ConnectionRetryPolicy,
)

# Environment variable for overriding max initial attempts
ENV_VAR_SESSION_MAX_INITIAL_ATTEMPTS = "FAME_SESSION_MAX_INITIAL_ATTEMPTS"


@dataclass
class DefaultConnectionRetryPolicyOptions:
    """Options for the default connection retry policy."""

    max_initial_attempts: int = 1
    """Maximum number of connection attempts before giving up.
    - 1 (default): Fail immediately on first error (fail-fast)
    - 0: Unlimited retries with exponential backoff
    - N > 1: Retry up to N times with exponential backoff
    """


class DefaultConnectionRetryPolicy(ConnectionRetryPolicy):
    """
    Default implementation of the connection retry policy.

    This policy determines whether to retry failed connection attempts based on:
    1. Whether a successful attach has occurred (always retry after attach)
    2. The current attempt number vs max_initial_attempts setting
    3. Environment variable override (FAME_SESSION_MAX_INITIAL_ATTEMPTS)

    The policy is stateless - all context is passed via the ConnectionRetryContext.
    """

    def __init__(self, options: Optional[DefaultConnectionRetryPolicyOptions] = None) -> None:
        """
        Initialize the default connection retry policy.

        Args:
            options: Configuration options. If None, defaults are used.
        """
        opts = options or DefaultConnectionRetryPolicyOptions()

        # Check for environment variable override
        env_value = os.getenv(ENV_VAR_SESSION_MAX_INITIAL_ATTEMPTS)
        if env_value is not None:
            try:
                self._max_initial_attempts = int(env_value)
            except ValueError:
                self._max_initial_attempts = opts.max_initial_attempts
        else:
            self._max_initial_attempts = opts.max_initial_attempts

    @property
    def max_initial_attempts(self) -> int:
        """Get the configured maximum initial attempts."""
        return self._max_initial_attempts

    def should_retry(self, context: ConnectionRetryContext) -> bool:
        """
        Determine whether to retry the connection.

        The decision logic:
        1. If we've had a successful attach, always retry (connection is recoverable)
        2. If max_initial_attempts is 0, always retry (unlimited mode)
        3. Otherwise, retry only if attempt_number < max_initial_attempts

        Args:
            context: The retry context containing attempt information

        Returns:
            True if the connection should be retried, False to fail immediately
        """
        # After first successful attach, always retry (existing behavior)
        if context.had_successful_attach:
            return True

        # max_initial_attempts = 0 means unlimited retries
        if self._max_initial_attempts == 0:
            return True

        # Retry if we haven't exceeded the max attempts
        return context.attempt_number < self._max_initial_attempts

    def calculate_retry_delay(self, context: ConnectionRetryContext, base_delay: float) -> float:
        """
        Calculate the delay before the next retry attempt.

        The default implementation returns the base delay unchanged.
        Exponential backoff is handled by the caller (UpstreamSessionManager).

        Args:
            context: The retry context (unused in default implementation)
            base_delay: The base delay in seconds

        Returns:
            The delay to use in seconds
        """
        return base_delay
