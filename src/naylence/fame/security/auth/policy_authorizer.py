"""
Policy authorizer interface.

An authorizer that delegates authorization decisions to a pluggable policy.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.policy.authorization_policy import AuthorizationPolicy


@runtime_checkable
class PolicyAuthorizer(Authorizer, Protocol):
    """
    An authorizer that delegates authorization decisions to a pluggable policy.

    This interface extends the base `Authorizer` interface and adds access
    to the underlying `AuthorizationPolicy` for inspection or debugging.
    """

    @property
    def policy(self) -> AuthorizationPolicy:
        """The currently active authorization policy."""
        ...
