"""
Factory for creating TraceEmitter instances using predefined profiles.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import Expressions, create_resource
from naylence.fame.telemetry.trace_emitter import TraceEmitter
from naylence.fame.telemetry.trace_emitter_factory import (
    TraceEmitterConfig,
    TraceEmitterFactory,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

# Environment variable names
ENV_VAR_TELEMETRY_SERVICE_NAME = "FAME_TELEMETRY_SERVICE_NAME"

# Profile names
PROFILE_NAME_NOOP = "noop"
PROFILE_NAME_OPEN_TELEMETRY = "open-telemetry"

# Profile configurations
NOOP_PROFILE = {
    "type": "NoopTraceEmitter",
}

OPEN_TELEMETRY_PROFILE = {
    "type": "OpenTelemetryTraceEmitter",
    "service_name": Expressions.env(ENV_VAR_TELEMETRY_SERVICE_NAME, default="naylence-service"),
    "headers": {},
}


class TraceEmitterProfileConfig(TraceEmitterConfig):
    """Configuration for TraceEmitter profile factory."""

    type: str = "TraceEmitterProfile"
    profile: Optional[str] = Field(default=None, description="Trace emitter profile name")


class TraceEmitterProfileFactory(TraceEmitterFactory):
    """Factory for creating TraceEmitter instances using predefined profiles."""

    type: str = "TraceEmitterProfile"

    async def create(
        self,
        config: Optional[TraceEmitterProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TraceEmitter:
        """Create a TraceEmitter instance based on the specified profile."""
        if isinstance(config, dict):
            config = TraceEmitterProfileConfig(**config)
        elif config is None:
            config = TraceEmitterProfileConfig(profile=PROFILE_NAME_NOOP)

        profile = config.profile

        if profile == PROFILE_NAME_NOOP:
            from .noop_trace_emitter_factory import NoopTraceEmitterConfig

            trace_emitter_config = NoopTraceEmitterConfig(**NOOP_PROFILE)
        elif profile == PROFILE_NAME_OPEN_TELEMETRY:
            from .open_telemetry_trace_emitter_factory import OpenTelemetryTraceEmitterConfig

            trace_emitter_config = OpenTelemetryTraceEmitterConfig(**OPEN_TELEMETRY_PROFILE)
        else:
            raise ValueError(f"Unknown trace emitter profile: {profile}")

        logger.debug("enabling_trace_emitter_profile", profile=profile)

        return await create_resource(TraceEmitterFactory, trace_emitter_config, **kwargs)
