"""
Base factory interface for SentinelStickinessManager implementations.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
    create_resource,
)
from naylence.fame.security.keys.key_provider import KeyProvider

from .load_balancer_stickiness_manager import LoadBalancerStickinessManager


class LoadBalancerStickinessManagerConfig(ResourceConfig):
    """Base configuration for LoadBalancerStickinessManager implementations."""

    type: str = "LoadBalancerStickinessManager"


C = TypeVar("C", bound=LoadBalancerStickinessManagerConfig)


class LoadBalancerStickinessManagerFactory(ResourceFactory[LoadBalancerStickinessManager, C]):
    """Abstract factory for creating SentinelStickinessManager instances."""

    @classmethod
    async def create_load_balancer_stickiness_manager(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        key_provider: Optional[KeyProvider] = None,
        **kwargs,
    ) -> Optional[LoadBalancerStickinessManager]:
        """Create a SentinelStickinessManager instance based on the provided configuration."""
        if isinstance(cfg, LoadBalancerStickinessManagerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg

        if cfg_dict is not None:
            return await create_resource(
                LoadBalancerStickinessManagerFactory,
                cfg_dict,
                key_provider=key_provider,
                **kwargs,
            )

        return await create_default_resource(
            LoadBalancerStickinessManagerFactory, key_provider=key_provider, **kwargs
        )
