"""
Factory for TraceEmitter implementations following Fame's ResourceFactory pattern.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_resource
from naylence.fame.telemetry.trace_emitter import TraceEmitter


class TraceEmitterConfig(ResourceConfig):
    """Base configuration for TraceEmitter implementations."""

    type: str = "TraceEmitter"


C = TypeVar("C", bound=TraceEmitterConfig)


class TraceEmitterFactory(ResourceFactory[TraceEmitter, C]):
    """Abstract factory for creating TraceEmitter instances."""

    async def create(self, config: Optional[C | dict[str, Any]] = None, **kwargs: Any) -> TraceEmitter:
        """Create a TraceEmitter instance."""
        raise NotImplementedError

    @classmethod
    async def create_trace_emitter(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        **kwargs,
    ) -> Optional[TraceEmitter]:
        """Create a TraceEmitter instance based on the provided configuration."""

        return await create_resource(
            TraceEmitterFactory,
            cfg,
            **kwargs,
        )
