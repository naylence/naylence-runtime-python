import random
from contextlib import contextmanager
from typing import Any, Mapping, Optional

from opentelemetry import trace
from opentelemetry.trace import SpanContext, Status, StatusCode, TraceFlags
from opentelemetry.util import types

from naylence.fame.telemetry.base_trace_emitter import BaseTraceEmitter

from .otel_context import otel_span_id_var, otel_trace_id_var
from .trace_emitter import Span


class _OpenTelemetrySpan(Span):
    def __init__(self, span: trace.Span):
        self._span = span

    def set_attribute(self, key: str, value: types.AttributeValue):
        self._span.set_attribute(key, value)

    def record_exception(self, exc: BaseException):
        self._span.record_exception(exc)

    def set_status_error(self, description: Optional[str] = None):
        self._span.set_status(Status(StatusCode.ERROR, description))


class OpenTelemetryTraceEmitter(BaseTraceEmitter):
    def __init__(self, service_name: str, tracer=None):
        super().__init__()
        self._tracer = tracer or trace.get_tracer(service_name)
        self._service_name = service_name

    def _convert_env_trace_id_to_otel(self, env_trace_id: str) -> int:
        """Convert envelope trace ID to OpenTelemetry trace ID.

        Args:
            env_trace_id: Trace ID string (15-16 chars)

        Returns:
            128-bit integer trace ID for OpenTelemetry
        """
        # Normalize to 16 chars: pad with '0' if shorter, trim if longer
        normalized = env_trace_id[:16].ljust(16, "0")

        # Convert string to bytes, then to integer
        trace_bytes = normalized.encode("utf-8")[:16]  # Ensure max 16 bytes
        return int.from_bytes(trace_bytes, byteorder="big")

    @contextmanager
    def start_span(self, name: str, attributes: Optional[Mapping[str, Any]] = None, links=None):
        span_context = None
        ctx = None

        # Check if env.trace_id is in attributes and use it for trace correlation
        env_trace_id = attributes.get("env.trace_id") if attributes else None
        if env_trace_id is not None:
            # Create custom span context with converted trace ID
            otel_trace_id = self._convert_env_trace_id_to_otel(env_trace_id)
            span_context = SpanContext(
                trace_id=otel_trace_id,
                span_id=random.getrandbits(64),  # Generate random 64-bit span ID
                is_remote=False,
                trace_flags=TraceFlags(0x01),  # Sampled
            )
            ctx = trace.set_span_in_context(trace.NonRecordingSpan(span_context))

        # Store tokens for cleanup
        t_tok = s_tok = None
        span = None
        try:
            # Create span without automatically setting it as current to avoid context issues
            span = self._tracer.start_span(name, context=ctx, links=links or [])

            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)

            # publish IDs for log correlation (no core OTel imports)
            span_ctx = span.get_span_context()
            try:
                if span_ctx and span_ctx.is_valid:
                    t_tok = otel_trace_id_var.set(f"{span_ctx.trace_id:032x}")
                    s_tok = otel_span_id_var.set(f"{span_ctx.span_id:016x}")
                yield _OpenTelemetrySpan(span)
            except GeneratorExit:
                # Handle forced generator closure gracefully
                if span:
                    span.set_status(trace.Status(trace.StatusCode.ERROR, "Span closed by GeneratorExit"))
                raise
            except Exception as e:
                # Set error status for any other exceptions
                if span:
                    span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
        finally:
            # End the span manually
            if span:
                try:
                    span.end()
                except Exception:
                    # Ignore any errors ending the span
                    pass

            # Clean up context variables safely
            if s_tok is not None:
                try:
                    otel_span_id_var.reset(s_tok)
                except (ValueError, LookupError):
                    # Token was created in different context, ignore
                    pass
            if t_tok is not None:
                try:
                    otel_trace_id_var.reset(t_tok)
                except (ValueError, LookupError):
                    # Token was created in different context, ignore
                    pass

    async def flush(self) -> None:
        """
        Flush any pending OpenTelemetry spans to exporters.

        This ensures all telemetry data is sent before shutdown.
        """
        try:
            from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider

            tracer_provider = trace.get_tracer_provider()
            if isinstance(tracer_provider, SDKTracerProvider):
                # Force flush with timeout
                tracer_provider.force_flush(timeout_millis=5000)
        except Exception:
            # Never let telemetry errors affect the runtime
            pass

    async def shutdown(self) -> None:
        """
        Shutdown the OpenTelemetry TracerProvider and clean up resources.

        This properly terminates all telemetry exporters and processors.
        """
        try:
            from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider

            tracer_provider = trace.get_tracer_provider()
            if isinstance(tracer_provider, SDKTracerProvider):
                # Shutdown the tracer provider
                tracer_provider.shutdown()
        except Exception:
            # Never let telemetry errors affect the runtime
            pass
