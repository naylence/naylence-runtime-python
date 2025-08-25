"""
Factory for creating NoSecurityManager instances.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.security_manager_config import SecurityManagerConfig

from .no_security_manager import NoSecurityManager
from .security_manager import SecurityManager
from .security_manager_factory import SecurityManagerFactory


class NoSecurityManagerConfig(SecurityManagerConfig):
    """Configuration for NoSecurityManager."""

    type: str = "NoSecurityManager"


class NoSecurityManagerFactory(SecurityManagerFactory[NoSecurityManagerConfig]):
    """Factory for creating NoSecurityManager instances."""

    @property
    def config_class(self) -> type[NoSecurityManagerConfig]:
        """Get the configuration class for this factory."""
        return NoSecurityManagerConfig

    async def create(
        self,
        config: Optional[NoSecurityManagerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> SecurityManager:
        """
        Create a NoSecurityManager instance.

        Args:
            config: Configuration (unused, included for interface compatibility)
            **kwargs: Additional keyword arguments (unused)

        Returns:
            A new NoSecurityManager instance
        """
        return NoSecurityManager()
