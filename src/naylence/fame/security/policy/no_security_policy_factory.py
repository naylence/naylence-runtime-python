"""
Factory for creating NoSecurityPolicy instances.
"""

from __future__ import annotations

from typing import Any, Optional

from .security_policy import SecurityPolicy, SecurityPolicyConfig
from .security_policy_factory import SecurityPolicyFactory


class NoSecurityPolicyConfig(SecurityPolicyConfig):
    """Configuration for NoSecurityPolicy."""

    type: str = "NoSecurityPolicy"


class NoSecurityPolicyFactory(SecurityPolicyFactory):
    """Factory for creating NoSecurityPolicy instances."""

    type: str = "NoSecurityPolicy"

    async def create(
        self,
        config: Optional[NoSecurityPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> SecurityPolicy:
        """Create a NoSecurityPolicy instance."""
        from .no_security_policy import NoSecurityPolicy

        return NoSecurityPolicy()
