from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Tuple

from naylence.fame.core import FameAddress, FameDeliveryContext, FameEnvelope
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
        "env.reply_to": str(env.reply_to) if env.reply_to else None,
        "env.ts": env.ts.isoformat() if env.ts else None,
        "env.frame_type": env.frame.type if env.frame else None,
        "env.is_signed": bool(env.sec and env.sec.sig),
        "env.sign_kid": env.sec.sig.kid if env.sec and env.sec.sig else None,
        "env.is_encrypted": bool(env.sec and env.sec.enc),
        "env.enc_kid": env.sec.enc.kid if env.sec and env.sec.enc else None,
    }


def _filter_none(d: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the dict with None values removed."""
    return {k: v for k, v in d.items() if v is not None}


@dataclass
class _ActiveSpan:
    """Holds the open context manager and the span it yielded so we can close later."""

    mgr: Any  # AbstractContextManager[Span], but keep Any to avoid typing fuss
    span: Span


class BaseTraceEmitter(NodeEventListener, TraceEmitter):
    def __init__(self):
        super().__init__()
        self._node: Optional[NodeLike] = None  # will be populated by on_node_started
        # Map of (envelope.id, operation_key) -> _ActiveSpan
        self._inflight: dict[Tuple[str, str], _ActiveSpan] = {}

    @property
    def priority(self) -> int:
        return 10000

    def _key(self, env: FameEnvelope, operation_key: str) -> Tuple[str, str]:
        return (env.id, operation_key)

    def _start_envelope_operation_span(
        self,
        node: Optional[NodeLike],
        operation_name: str,
        envelope: FameEnvelope,
        operation_key: str,
        additional_attributes: Optional[dict[str, Any]] = None,
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

        node = node or self._node
        if node:
            attributes["node.id"] = node.id
            attributes["node.sid"] = getattr(node, "_sid", None)

        mgr = self.start_span(operation_name, attributes=_filter_none(attributes))
        span = mgr.__enter__()

        self._inflight[key] = _ActiveSpan(mgr=mgr, span=span)
        return envelope  # important: do not swallow the envelope

    def _complete_envelope_operation_span(
        self,
        node: Optional[NodeLike],
        operation_name: str,
        envelope: FameEnvelope,
        operation_key: str,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        additional_attributes: Optional[dict[str, Any]] = None,
    ) -> Optional[FameEnvelope]:
        """Complete a span for an operation, handling success/error cases."""
        key = self._key(envelope, operation_key)
        active = self._inflight.pop(key, None)

        if active is None:
            # No matching start; create a short-lived span so we still record outcome.
            attributes = _env_attrs(envelope)
            if additional_attributes:
                attributes.update(additional_attributes)

            node = node or self._node
            if node:
                attributes["node.id"] = node.id
                attributes["node.sid"] = getattr(node, "_sid", None)

            mgr = self.start_span(operation_name, attributes=_filter_none(attributes))
            span = mgr.__enter__()
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

        return envelope  # important: do not swallow the envelope

    async def on_envelope_received(
        self, node: NodeLike, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> Optional[FameEnvelope]:
        """Record envelope reception as a simple span."""
        # Build attributes for the reception event
        attributes = _env_attrs(envelope)

        if node:
            attributes["node.id"] = node.id
            # Some envelopes arrive before node sid is set
            # but using node.sid would raise an exception so we use getattr with default None
            attributes["node.sid"] = getattr(node, "_sid", None)

        if context and context.from_system_id:
            attributes["from.node_id"] = context.from_system_id

        if context and context.origin_type:
            attributes["from.origin_type"] = context.origin_type

        # Create a short-lived span for the reception event
        with self.start_span("env.received", attributes=_filter_none(attributes)):
            # The span automatically ends when exiting the context manager
            pass

        return envelope

    async def on_forward_to_route(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        return self._start_envelope_operation_span(
            node=node,
            operation_name="env.fwd_to_route",
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
    ) -> Optional[FameEnvelope]:
        return self._complete_envelope_operation_span(
            node=node,
            operation_name="env.fwd_to_route",
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
    ) -> Optional[FameEnvelope]:
        return self._start_envelope_operation_span(
            node=node,
            operation_name="env.fwd_upstream",
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
    ) -> Optional[FameEnvelope]:
        return self._complete_envelope_operation_span(
            node=node,
            operation_name="env.fwd_upstream",
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
    ) -> Optional[FameEnvelope]:
        return self._start_envelope_operation_span(
            node=node,
            operation_name="env.fwd_to_peer",
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
    ) -> Optional[FameEnvelope]:
        return self._complete_envelope_operation_span(
            node=node,
            operation_name="env.fwd_to_peer",
            envelope=envelope,
            operation_key=peer_segment,
            result=result,
            error=error,
            additional_attributes={"peer.segment": peer_segment},
        )

    async def on_deliver_local(
        self,
        node: NodeLike,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """Track local delivery operations."""
        return self._start_envelope_operation_span(
            node=node,
            operation_name="env.deliver_local",
            envelope=envelope,
            operation_key=str(address),
            additional_attributes={
                "delivery.address": str(address),
                "delivery.type": "local",
            },
        )

    async def on_deliver_local_complete(
        self,
        node: NodeLike,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """Complete local delivery span tracking."""
        return self._complete_envelope_operation_span(
            node=node,
            operation_name="env.deliver_local",
            envelope=envelope,
            operation_key=str(address),
            additional_attributes={
                "delivery.address": str(address),
                "delivery.type": "local",
            },
        )

    async def on_node_initialized(self, node: NodeLike) -> None:
        self._node = node

    async def on_node_stopped(self, node: NodeLike) -> None:
        """
        Handle node shutdown - clean up telemetry resources.

        This method implements the NodeEventListener interface and ensures
        proper telemetry shutdown when the node stops.

        Args:
            node: The node that is being stopped
        """
        try:
            await self.flush()
            await self.shutdown()
        except Exception:
            # Never let telemetry errors affect node shutdown
            pass

    async def flush(self) -> None:
        """
        Flush any pending telemetry data.

        Override in subclasses to implement specific flushing logic.
        Base implementation does nothing.
        """
        pass

    async def shutdown(self) -> None:
        """
        Shutdown telemetry and clean up resources.

        Override in subclasses to implement specific shutdown logic.
        Base implementation does nothing.
        """
        pass
