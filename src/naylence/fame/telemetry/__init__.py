"""
Telemetry package for Fame framework.

This package provides trace emission capabilities through the TraceEmitter protocol
and includes implementations for both no-op and OpenTelemetry backends.
"""

from .noop_trace_emitter import NoopTraceEmitter
from .noop_trace_emitter_factory import NoopTraceEmitterConfig, NoopTraceEmitterFactory
from .open_telemetry_trace_emitter import OpenTelemetryTraceEmitter
from .open_telemetry_trace_emitter_factory import (
    OpenTelemetryTraceEmitterConfig,
    OpenTelemetryTraceEmitterFactory,
)
from .trace_emitter import Span, TraceEmitter
from .trace_emitter_factory import TraceEmitterConfig, TraceEmitterFactory
from .trace_emitter_profile_factory import (
    TraceEmitterProfileConfig,
    TraceEmitterProfileFactory,
)

__all__ = [
    "TraceEmitter",
    "Span",
    "TraceEmitterFactory",
    "TraceEmitterConfig",
    "NoopTraceEmitter",
    "NoopTraceEmitterFactory",
    "NoopTraceEmitterConfig",
    "OpenTelemetryTraceEmitter",
    "OpenTelemetryTraceEmitterFactory",
    "OpenTelemetryTraceEmitterConfig",
    "TraceEmitterProfileFactory",
    "TraceEmitterProfileConfig",
]


__all__ = [
    "TraceEmitter",
    "Span",
    "TraceEmitterFactory",
    "TraceEmitterConfig",
    "NoopTraceEmitter",
    "NoopTraceEmitterFactory",
    "NoopTraceEmitterConfig",
    "OpenTelemetryTraceEmitter",
    "OpenTelemetryTraceEmitterFactory",
    "OpenTelemetryTraceEmitterConfig",
    "TraceEmitterProfileFactory",
    "TraceEmitterProfileConfig",
]


__all__ = [
    "TraceEmitter",
    "Span",
    "TraceEmitterFactory",
    "TraceEmitterConfig",
    "NoopTraceEmitter",
    "NoopTraceEmitterFactory",
    "NoopTraceEmitterConfig",
    "OpenTelemetryTraceEmitter",
    "OpenTelemetryTraceEmitterFactory",
    "OpenTelemetryTraceEmitterConfig",
]
