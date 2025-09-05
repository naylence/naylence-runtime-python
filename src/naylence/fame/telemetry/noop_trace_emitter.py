from contextlib import contextmanager
from typing import Any, Mapping, Optional

from naylence.fame.telemetry.trace_emitter import Span, TraceEmitter


class _NoopSpan(Span):
    def set_attribute(self, *a, **k):
        pass

    def record_exception(self, *a, **k):
        pass

    def set_status_error(self, *a, **k):
        pass


class NoopTraceEmitter(TraceEmitter):
    @contextmanager
    def start_span(self, name: str, attributes: Optional[Mapping[str, Any]] = None, links=None):
        yield _NoopSpan()
