from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.telemetry.trace_emitter import Span, TraceEmitter


def _env_attrs(env: FameEnvelope):
    return {
        "env.id": env.id,
        "env.trace_id": env.trace_id,
        "env.corr_id": env.corr_id,
        "env.flow_id": env.flow_id,
        "env.seq_id": env.seq_id,
        "env.to": str(env.to) if env.to else None,
        "env.priority": str(env.priority) if env.priority else None,
        "env.sid": env.sid,
    }


@dataclass
class _ActiveSpan:
    """Holds the open context manager and the span it yielded so we can close later."""

    mgr: Any  # AbstractContextManager[Span], but keep Any to avoid typing fuss
    span: Span


class TracingListener(NodeEventListener):
    def __init__(self, emitter: TraceEmitter):
        self.emitter = emitter
        # Map of (envelope.id, next_segment) -> _ActiveSpan
        self._inflight: Dict[Tuple[str, str], _ActiveSpan] = {}

    def _key(self, env: FameEnvelope, segment: str) -> Tuple[str, str]:
        return (env.id, segment)

    async def on_forward_to_route(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        # Start the span here and keep it open until the corresponding *complete event.
        key = self._key(envelope, next_segment)

        # If we somehow get a duplicate start, close previous to avoid leaks.
        previous = self._inflight.pop(key, None)
        if previous is not None:
            try:
                # Best-effort close
                previous.mgr.__exit__(None, None, None)
            except Exception:
                pass

        mgr = self.emitter.start_span("fwd.to_route", attributes=_env_attrs(envelope))
        span = mgr.__enter__()
        span.set_attribute("route.segment", next_segment)
        self._inflight[key] = _ActiveSpan(mgr=mgr, span=span)

        return envelope  # important: do not swallow the envelope

    async def on_forward_to_route_complete(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        key = self._key(envelope, next_segment)
        active = self._inflight.pop(key, None)

        if active is None:
            # No matching start; create a short-lived span so we still record outcome.
            mgr = self.emitter.start_span("fwd.to_route", attributes=_env_attrs(envelope))
            span = mgr.__enter__()
            span.set_attribute("route.segment", next_segment)
            # fall through to common close path at the end
        else:
            mgr, span = active.mgr, active.span

        # Annotate outcome
        if error is not None:
            try:
                span.record_exception(error)
                span.set_status_error(str(error))
            except Exception:
                # Never let tracing errors affect the runtime
                pass

        # End the span
        try:
            mgr.__exit__(None, None, None)
        except Exception:
            pass
