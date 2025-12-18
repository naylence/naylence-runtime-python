"""
Connection retry policy interface for configurable reconnection behavior.

This module defines the protocol for connection retry policies that determine
whether to retry connection attempts and how long to wait between retries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable


@dataclass
class ConnectionRetryContext:
    """
    Context provided to the retry policy for making retry decisions.

    Attributes:
        had_successful_attach: Whether the connection has successfully attached before.
            If True, reconnection is typically more aggressive since the infrastructure
            is known to be reachable.
        attempt_number: The current attempt number (1-based). The first attempt is 1.
        error: The error that triggered the retry consideration.
        connection_duration_ms: How long the connection was active before failure,
            if applicable. None for initial connection attempts.
    """

    had_successful_attach: bool
    attempt_number: int
    error: Optional[BaseException] = None
    connection_duration_ms: Optional[float] = None


@runtime_checkable
class ConnectionRetryPolicy(Protocol):
    """
    Protocol for connection retry policies.

    A retry policy determines whether to retry a failed connection attempt
    and can influence the retry delay calculation.

    The policy is stateless - all decision-making context is passed via
    the ConnectionRetryContext parameter.
    """

    def should_retry(self, context: ConnectionRetryContext) -> bool:
        """
        Determine whether to retry the connection.

        Args:
            context: The retry context containing attempt information

        Returns:
            True if the connection should be retried, False to fail immediately
        """
        ...

    def calculate_retry_delay(self, context: ConnectionRetryContext, base_delay: float) -> float:
        """
        Calculate the delay before the next retry attempt.

        The default implementation typically applies exponential backoff with jitter.
        Custom policies can override this to implement different backoff strategies.

        Args:
            context: The retry context containing attempt information
            base_delay: The base delay in seconds before any modifications

        Returns:
            The actual delay to use in seconds
        """
        ...
