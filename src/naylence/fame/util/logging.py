"""
naylence.fame.util.logging
--------------------------

Unified std-lib + Structlog setup with a custom TRACE (level 5) and
JSON-formatted, envelope-aware log lines.

Use::

    from naylence.fame.util.logging import getLogger, basicConfig, TRACE
    basicConfig()                           # once at startup
    log = getLogger(__name__)
    log.trace("something %s", obj)          # TRACE
    log.debug("debug msg", extra="field")   # DEBUG
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Protocol, Sequence, runtime_checkable

import structlog
from structlog.contextvars import merge_contextvars
from structlog.dev import ConsoleRenderer
from structlog.processors import TimeStamper, add_log_level
from structlog.stdlib import BoundLogger, LoggerFactory
from structlog.typing import EventDict, WrappedLogger

from naylence.fame.core import FameEnvelope
from naylence.fame.util.envelope_context import EnvelopeSnapshot, current_envelope

# ───────────────────────────────────────────────────────────────────────────────
# 1. TRACE level (numeric 5) wired into BOTH std-lib & structlog
# ───────────────────────────────────────────────────────────────────────────────
TRACE: int = 5
logging.addLevelName(TRACE, "TRACE")  # std-lib knows the name

# Tell structlog’s stdlib helpers about it
structlog.stdlib.NAME_TO_LEVEL["trace"] = TRACE  # type: ignore
structlog.stdlib.LEVEL_TO_NAME[TRACE] = "trace"  # type: ignore


def _patch_logger_class(cls: type[logging.Logger]) -> None:
    """Give *cls* a .trace(...) method if it doesn’t have one."""
    if hasattr(cls, "trace"):
        return

    def _trace(self: logging.Logger, msg: str, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)

    cls.trace = _trace  # type: ignore[attr-defined]


# patch the *active* logger class (may be structlog’s shim) + base Logger
_patch_logger_class(logging.getLoggerClass())
_patch_logger_class(logging.Logger)


# ───────────────────────────────────────────────────────────────────────────────
# 2. BoundLogger.trace → goes through structlog pipeline
# ───────────────────────────────────────────────────────────────────────────────
def _bound_trace(self: BoundLogger, event: str | None = None, *args: Any, **kw) -> BoundLogger:
    if args and event is not None:  # emulate %-interpolation for positional args
        try:
            event = event % args
        except Exception:  # pragma: no cover
            pass
    return self.log(TRACE, event, **kw)  # type: ignore[arg-type]


BoundLogger.trace = _bound_trace  # type: ignore[attr-defined]

# ───────────────────────────────────────────────────────────────────────────────
# 3. Structlog processors
# ───────────────────────────────────────────────────────────────────────────────
_JSON_PRIMITIVES: tuple[type[Any], ...] = (
    str,
    int,
    float,
    bool,
    type(None),
    dict,
    list,
)


def _add_envelope_fields(_logger: WrappedLogger, _method: str, ev: EventDict) -> EventDict:
    snap: Optional[EnvelopeSnapshot] = current_envelope.get()
    if not snap:
        return ev

    ev.update(
        {
            "trace_id": snap.trace_id,
            "ctx_envp_id": snap.id,
            "ctx_flow_id": snap.flow_id,
        }
    )
    return ev


def _drop_empty(_: WrappedLogger, __: str, ev: EventDict) -> EventDict:
    """Remove keys whose value is None/''/[]/{} so logs stay compact."""
    return {k: v for k, v in ev.items() if v not in (None, "", [], {})}


def _stringify_non_primitives(_logger: WrappedLogger, _method: str, ev: EventDict) -> EventDict:
    """Ensure everything is JSON-serialisable before JSONRenderer runs."""
    for k, v in list(ev.items()):
        if not isinstance(v, _JSON_PRIMITIVES):
            ev[k] = str(v)
    return ev


def _add_otel_ids(_logger: WrappedLogger, _method: str, ev: EventDict) -> EventDict:
    from naylence.fame.telemetry.otel_context import otel_span_id_var, otel_trace_id_var

    tid = otel_trace_id_var.get()
    sid = otel_span_id_var.get()
    if tid:
        ev.setdefault("otel.trace_id", tid)
    if sid:
        ev.setdefault("otel.span_id", sid)
    return ev


structlog.configure(
    context_class=dict,
    logger_factory=LoggerFactory(),
    wrapper_class=BoundLogger,
    cache_logger_on_first_use=True,
    processors=[
        merge_contextvars,  # 0 – pull contextvars (if any)
        _add_envelope_fields,  # 1 – inject envelope metadata
        _add_otel_ids,
        _drop_empty,  # 2 – strip empty values
        _stringify_non_primitives,  # 3 – make every value JSON-safe
        add_log_level,  # 4 – inject "level"
        TimeStamper(fmt="iso"),  # 5 – inject "timestamp"
        ConsoleRenderer(colors=True, sort_keys=False, pad_event=30),  # pretty-prints & colorises
    ],
)


@runtime_checkable
class TraceLogger(Protocol):
    def trace(self, event: str | None = None, *args: Any, **kw: Any) -> TraceLogger: ...

    # Include the regular std-lib methods so the protocol is a superset
    def debug(self, *args: Any, **kw: Any) -> TraceLogger: ...
    def info(self, *args: Any, **kw: Any) -> TraceLogger: ...
    def warning(self, *args: Any, **kw: Any) -> TraceLogger: ...
    def error(self, *args: Any, **kw: Any) -> TraceLogger: ...
    def exception(self, *args: Any, **kw: Any) -> TraceLogger: ...
    def critical(self, *args: Any, **kw: Any) -> TraceLogger: ...
    def setLevel(self, *args: Any, **kw: Any) -> TraceLogger: ...


# ───────────────────────────────────────────────────────────────────────────────
# 4. Public helpers
# ───────────────────────────────────────────────────────────────────────────────
def getLogger(name: str | Sequence[str]) -> TraceLogger:  # pragma: no cover
    """Return a structlog BoundLogger."""
    return structlog.get_logger(name)


def basicConfig(*args: Any, **kwargs: Any) -> None:  # pragma: no cover
    """
    Thin wrapper around ``logging.basicConfig`` that:

    * sets ``format="%(message)s"`` (structlog emits final text)
    * sets root level to TRACE by default
    """
    kwargs.setdefault("format", "%(message)s")
    kwargs.setdefault("level", TRACE)
    logging.basicConfig(*args, **kwargs)


# re-export common level constants
CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG
NOTSET = logging.NOTSET
__all__ = [
    "TRACE",
    "basicConfig",
    "getLogger",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG",
    "NOTSET",
]


def summarize_env(env: FameEnvelope, prefix: Optional[str] = "child_") -> EventDict:
    return {
        f"{prefix}envp_id": env.id,
        f"{prefix}sid": f"{env.sid}…" if env.sid else None,
        f"{prefix}to": str(env.to) if env.to else None,
        f"{prefix}trace_id": env.trace_id,
        f"{prefix}frame": getattr(env.frame, "type", type(env.frame).__name__),
        f"{prefix}corr_id": env.corr_id,
    }


def enable_logging(log_level: str | int):
    if isinstance(log_level, int):
        log_level_i = log_level
    elif isinstance(log_level, str):
        log_level_i = logging.getLevelNamesMapping().get(log_level.upper())
    getLogger("naylence").setLevel(log_level_i)
    basicConfig(level=logging.WARNING)
