from contextvars import ContextVar
from typing import Optional

otel_trace_id_var: ContextVar[Optional[str]] = ContextVar("otel.trace_id", default=None)
otel_span_id_var: ContextVar[Optional[str]] = ContextVar("otel.span_id", default=None)
