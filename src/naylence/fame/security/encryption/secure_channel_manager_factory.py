"""
Base factory interface for SecureChannelManager implementations.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource

from .secure_channel_manager import SecureChannelManager


class SecureChannelManagerConfig(ResourceConfig):
    """Base configuration for SecureChannelManager implementations."""

    type: str = "SecureChannelManager"


C = TypeVar("C", bound=SecureChannelManagerConfig)


class SecureChannelManagerFactory(ResourceFactory[SecureChannelManager, C]):
    """Abstract factory for creating SecureChannelManager instances."""

    @classmethod
    async def create_secure_channel_manager(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        **kwargs,
    ) -> Optional[SecureChannelManager]:
        """Create a SecureChannelManager instance based on the provided configuration."""
        if isinstance(cfg, SecureChannelManagerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(SecureChannelManagerFactory, cfg_dict, **kwargs)
