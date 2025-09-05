from contextlib import contextmanager
from typing import Any, Mapping, Optional

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from .otel_context import otel_span_id_var, otel_trace_id_var
from .trace_emitter import Span, TraceEmitter


class _OpenTelemetrySpan(Span):
    def __init__(self, span):
        self._span = span

    def set_attribute(self, key, value):
        self._span.set_attribute(key, value)

    def record_exception(self, exc):
        self._span.record_exception(exc)

    def set_status_error(self, description=None):
        self._span.set_status(Status(StatusCode.ERROR, description))


class OpenTelemetryTraceEmitter(TraceEmitter):
    def __init__(self, service_name: str, tracer=None):
        self._tracer = tracer or trace.get_tracer(service_name)

    @contextmanager
    def start_span(self, name: str, attributes: Optional[Mapping[str, Any]] = None, links=None):
        with self._tracer.start_as_current_span(name, links=links or []) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)

            # publish IDs for log correlation (no core OTel imports)
            t_tok = s_tok = None
            ctx = span.get_span_context()
            try:
                if ctx and ctx.is_valid:
                    t_tok = otel_trace_id_var.set(f"{ctx.trace_id:032x}")
                    s_tok = otel_span_id_var.set(f"{ctx.span_id:016x}")
                yield _OpenTelemetrySpan(span)
            finally:
                if s_tok is not None:
                    try:
                        otel_span_id_var.reset(s_tok)
                    except Exception:
                        pass
                if t_tok is not None:
                    try:
                        otel_trace_id_var.reset(t_tok)
                    except Exception:
                        pass
