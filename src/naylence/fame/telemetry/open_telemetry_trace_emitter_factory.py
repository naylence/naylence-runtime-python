from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)

from .trace_emitter import TraceEmitter
from .trace_emitter_factory import TraceEmitterConfig, TraceEmitterFactory


class OpenTelemetryTraceEmitterConfig(TraceEmitterConfig):
    """Configuration for OpenTelemetryTraceEmitter."""

    type: str = "OpenTelemetryTraceEmitter"

    service_name: str = "naylence-service"
    endpoint: Optional[str] = None
    environment: Optional[str] = None
    sampler: Optional[str] = None
    headers: Optional[dict[str, str]] = None

    auth: Optional[AuthInjectionStrategyConfig] = None


class OpenTelemetryTraceEmitterFactory(TraceEmitterFactory):
    """Factory for creating OpenTelemetryTraceEmitter instances."""

    type: str = "OpenTelemetryTraceEmitter"

    async def create(
        self,
        config: Optional[OpenTelemetryTraceEmitterConfig | dict[str, Any]] = None,
        service_name: Optional[str] = None,
        endpoint: Optional[str] = None,
        environment: Optional[str] = None,
        sampler: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        tracer: Optional[Any] = None,
        **kwargs: Any,
    ) -> TraceEmitter:
        """Create an OpenTelemetryTraceEmitter instance."""
        from .open_telemetry_trace_emitter import OpenTelemetryTraceEmitter

        if config is None:
            config = OpenTelemetryTraceEmitterConfig()
        elif isinstance(config, dict):
            config = OpenTelemetryTraceEmitterConfig(**config)

        service_name = service_name or config.service_name
        tracer = kwargs.get("tracer")

        merged_headers = {**(config.headers or {}), **(headers or {})}

        if config.auth:
            auth_strategy = await AuthInjectionStrategyFactory.create_auth_strategy(config.auth)
            # Set a default "Authorization" header on the dictionary
            await auth_strategy.apply(merged_headers)

        from .otel_setup import setup_otel

        setup_otel(
            service_name=service_name,
            endpoint=endpoint or config.endpoint,
            environment=environment or config.environment,
            sampler=sampler or config.sampler or "parentbased_always_on",
            headers=merged_headers if merged_headers else None,
        )

        return OpenTelemetryTraceEmitter(service_name=service_name, tracer=tracer)
