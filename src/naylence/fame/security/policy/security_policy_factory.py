"""
Security policy factory interface.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource

from .security_policy import SecurityPolicy

# Type variables for the factory pattern
C = TypeVar("C", bound=ResourceConfig)


class SecurityPolicyFactory(ResourceFactory[SecurityPolicy, C]):
    """Abstract ResourceFactory façade for dependency-injection."""

    async def create(self, config: Optional[C | dict[str, Any]] = None, **kwargs: Any) -> SecurityPolicy:
        """Create a SecurityPolicy instance."""
        raise NotImplementedError

    @classmethod
    async def create_security_policy(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        *,
        key_provider=None,
        **kwargs,
    ) -> Optional[SecurityPolicy]:
        """Create a SecurityPolicy instance based on the provided configuration."""
        if isinstance(cfg, ResourceConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(
            SecurityPolicyFactory, cfg_dict, key_provider=key_provider, **kwargs
        )
