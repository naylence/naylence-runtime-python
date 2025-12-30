"""
Factory for creating TraceEmitter instances using predefined profiles.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.factory import Expressions, create_resource
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
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

# Trace emitter factory base type constant
TRACE_EMITTER_FACTORY_BASE_TYPE = "TraceEmitterFactory"

# Register built-in profiles
_profiles_registered = False


def _ensure_profiles_registered() -> None:
    """Ensure built-in trace emitter profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="trace-emitter-profile-factory")
    register_profile(TRACE_EMITTER_FACTORY_BASE_TYPE, PROFILE_NAME_NOOP, NOOP_PROFILE, opts)
    register_profile(
        TRACE_EMITTER_FACTORY_BASE_TYPE, PROFILE_NAME_OPEN_TELEMETRY, OPEN_TELEMETRY_PROFILE, opts
    )
    _profiles_registered = True


_ensure_profiles_registered()


def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve trace emitter profile by name."""
    _ensure_profiles_registered()

    profile = get_profile(TRACE_EMITTER_FACTORY_BASE_TYPE, profile_name)
    if profile is not None:
        return profile

    # Try to discover from entry points
    discover_profile(TRACE_EMITTER_FACTORY_BASE_TYPE, profile_name)

    profile = get_profile(TRACE_EMITTER_FACTORY_BASE_TYPE, profile_name)
    if profile is None:
        raise ValueError(f"Unknown trace emitter profile: {profile_name}")

    return profile


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
        trace_emitter_config = _resolve_profile_config(profile)

        logger.debug("enabling_trace_emitter_profile", profile=profile)

        return await create_resource(TraceEmitterFactory, trace_emitter_config, **kwargs)
