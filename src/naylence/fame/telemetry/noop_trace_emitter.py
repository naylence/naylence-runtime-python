from contextlib import contextmanager
from typing import Any, Mapping, Optional

from naylence.fame.telemetry.base_trace_emitter import BaseTraceEmitter
from naylence.fame.telemetry.trace_emitter import Span


class _NoopSpan(Span):
    def set_attribute(self, *a, **k):
        pass

    def record_exception(self, *a, **k):
        pass

    def set_status_error(self, *a, **k):
        pass


class NoopTraceEmitter(BaseTraceEmitter):
    def __init__(self) -> None:
        super().__init__()

    @contextmanager
    def start_span(self, name: str, attributes: Optional[Mapping[str, Any]] = None, links=None):
        yield _NoopSpan()
