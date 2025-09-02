"""
Base factory interface for ReplicaStickinessManager implementations.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource

from .replica_stickiness_manager import ReplicaStickinessManager


class ReplicaStickinessManagerConfig(ResourceConfig):
    """Base configuration for ReplicaStickinessManager implementations."""

    type: str = "ReplicaStickinessManager"


C = TypeVar("C", bound=ReplicaStickinessManagerConfig)


class ReplicaStickinessManagerFactory(ResourceFactory[ReplicaStickinessManager, C]):
    """Abstract factory for creating ReplicaStickinessManager instances."""

    @classmethod
    async def create_replica_stickiness_manager(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        **kwargs,
    ) -> Optional[ReplicaStickinessManager]:
        """Create a ReplicaStickinessManager instance based on the provided configuration."""
        if isinstance(cfg, ReplicaStickinessManagerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(ReplicaStickinessManagerFactory, cfg_dict, **kwargs)
