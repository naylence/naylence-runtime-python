from contextlib import AbstractContextManager
from typing import Any, Mapping, Optional, Protocol


class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...
    def record_exception(self, exc: BaseException) -> None: ...
    def set_status_error(self, description: Optional[str] = None) -> None: ...


class TraceEmitter(Protocol):
    def start_span(
        self,
        name: str,
        attributes: Optional[Mapping[str, Any]] = None,
        links: Optional[list[Any]] = None,  # opaque; backends decide
    ) -> AbstractContextManager[Span]: ...
