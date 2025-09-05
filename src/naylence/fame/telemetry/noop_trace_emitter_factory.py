"""
Factory for creating NoopTraceEmitter instances.
"""

from __future__ import annotations

from typing import Any, Optional

from .trace_emitter import TraceEmitter
from .trace_emitter_factory import TraceEmitterConfig, TraceEmitterFactory


class NoopTraceEmitterConfig(TraceEmitterConfig):
    """Configuration for NoopTraceEmitter."""

    type: str = "NoopTraceEmitter"


class NoopTraceEmitterFactory(TraceEmitterFactory):
    """Factory for creating NoopTraceEmitter instances."""

    type: str = "NoopTraceEmitter"
    is_default: bool = True

    async def create(
        self,
        config: Optional[NoopTraceEmitterConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TraceEmitter:
        """Create a NoopTraceEmitter instance."""
        from .noop_trace_emitter import NoopTraceEmitter

        return NoopTraceEmitter()
