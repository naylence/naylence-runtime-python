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


class BaseTraceEmitter(NodeEventListener, TraceEmitter):
    def __init__(self):
        super().__init__()
        # Map of (envelope.id, operation_key) -> _ActiveSpan
        self._inflight: Dict[Tuple[str, str], _ActiveSpan] = {}

    def _key(self, env: FameEnvelope, operation_key: str) -> Tuple[str, str]:
        return (env.id, operation_key)

    def _start_operation_span(
        self,
        operation_name: str,
        envelope: FameEnvelope,
        operation_key: str,
        additional_attributes: Optional[Dict[str, Any]] = None,
    ) -> FameEnvelope:
        """Start a span for an operation and track it until completion."""
        key = self._key(envelope, operation_key)

        # If we somehow get a duplicate start, close previous to avoid leaks.
        previous = self._inflight.pop(key, None)
        if previous is not None:
            try:
                # Best-effort close
                previous.mgr.__exit__(None, None, None)
            except Exception:
                pass

        # Build attributes
        attributes = _env_attrs(envelope)
        if additional_attributes:
            attributes.update(additional_attributes)

        mgr = self.start_span(operation_name, attributes=attributes)
        span = mgr.__enter__()

        # Apply additional attributes to the span
        if additional_attributes:
            for key_attr, value in additional_attributes.items():
                if value is not None:
                    span.set_attribute(key_attr, value)

        self._inflight[key] = _ActiveSpan(mgr=mgr, span=span)
        return envelope  # important: do not swallow the envelope

    def _complete_operation_span(
        self,
        operation_name: str,
        envelope: FameEnvelope,
        operation_key: str,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        additional_attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Complete a span for an operation, handling success/error cases."""
        key = self._key(envelope, operation_key)
        active = self._inflight.pop(key, None)

        if active is None:
            # No matching start; create a short-lived span so we still record outcome.
            attributes = _env_attrs(envelope)
            if additional_attributes:
                attributes.update(additional_attributes)

            mgr = self.start_span(operation_name, attributes=attributes)
            span = mgr.__enter__()

            # Apply additional attributes to the span
            if additional_attributes:
                for key_attr, value in additional_attributes.items():
                    if value is not None:
                        span.set_attribute(key_attr, value)
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

    async def on_forward_to_route(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        return self._start_operation_span(
            operation_name="fwd.to_route",
            envelope=envelope,
            operation_key=next_segment,
            additional_attributes={"route.segment": next_segment},
        )

    async def on_forward_to_route_complete(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        self._complete_operation_span(
            operation_name="fwd.to_route",
            envelope=envelope,
            operation_key=next_segment,
            result=result,
            error=error,
            additional_attributes={"route.segment": next_segment},
        )

    async def on_forward_upstream(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        return self._start_operation_span(
            operation_name="fwd.upstream",
            envelope=envelope,
            operation_key="upstream",
            additional_attributes={"direction": "upstream"},
        )

    async def on_forward_upstream_complete(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        self._complete_operation_span(
            operation_name="fwd.upstream",
            envelope=envelope,
            operation_key="upstream",
            result=result,
            error=error,
            additional_attributes={"direction": "upstream"},
        )

    async def on_forward_to_peer(
        self,
        node: NodeLike,
        peer_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ):
        return self._start_operation_span(
            operation_name="fwd.to_peer",
            envelope=envelope,
            operation_key=peer_segment,
            additional_attributes={"peer.segment": peer_segment},
        )

    async def on_forward_to_peer_complete(
        self,
        node: NodeLike,
        peer_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        self._complete_operation_span(
            operation_name="fwd.to_peer",
            envelope=envelope,
            operation_key=peer_segment,
            result=result,
            error=error,
            additional_attributes={"peer.segment": peer_segment},
        )
