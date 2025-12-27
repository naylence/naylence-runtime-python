"""
Authorization policy source interface.

Policy sources abstract where the policy definition comes from,
allowing policies to be loaded from local files, remote stores,
or other sources.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)


@runtime_checkable
class AuthorizationPolicySource(Protocol):
    """
    Interface for sources that provide authorization policies.

    Policy sources abstract where the policy definition comes from,
    allowing policies to be loaded from local files, remote stores,
    or other sources.
    """

    async def load_policy(self) -> AuthorizationPolicy:
        """
        Loads and returns the authorization policy.

        This method may be called multiple times, for example when
        reloading a policy after changes. Implementations should
        handle caching internally if needed.

        Returns:
            The loaded authorization policy
        """
        ...
