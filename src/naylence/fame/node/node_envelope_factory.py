from datetime import datetime, timezone
from typing import Callable, Optional

from naylence.fame.core import (
    EnvelopeFactory,
    FameAddress,
    FameEnvelope,
    FameFrame,
    FameResponseType,
    FlowFlags,
    generate_id,
)
from naylence.fame.util.envelope_context import current_trace_id


class NodeEnvelopeFactory(EnvelopeFactory):
    def __init__(
        self,
        physical_path_fn: Callable[[], str],
        sid_fn: Callable[[], str],
    ) -> None:
        self._physical_path_fn = physical_path_fn
        self._sid_fn = sid_fn

    def create_envelope(
        self,
        *,
        frame: FameFrame,
        id: Optional[str] = None,
        trace_id: Optional[str] = None,
        to: Optional[FameAddress | str] = None,
        capabilities: Optional[list[str]] = None,
        reply_to: Optional[FameAddress] = None,
        flow_id: Optional[str] = None,
        window_id: Optional[int] = 0,
        flags: Optional[FlowFlags] = FlowFlags.NONE,
        timestamp: Optional[datetime] = None,
        corr_id: Optional[str] = None,
        response_type: Optional[FameResponseType] = None,
        # **kwargs,
    ) -> FameEnvelope:
        env = FameEnvelope(
            id=id or generate_id(),
            sid=self._sid_fn(),
            trace_id=trace_id or current_trace_id() or generate_id(),
            to=FameAddress(to) if to else None,
            capabilities=capabilities,
            rtype=response_type,
            reply_to=reply_to,
            frame=frame,  # type: ignore
            flow_id=flow_id,
            seq_id=window_id,
            flow_flags=flags,
            corr_id=corr_id,
            ts=timestamp or datetime.now(timezone.utc),
            # **kwargs,
        )

        # NOTE: Signing and encryption are now handled in forward* methods
        # All outbound security is applied at the forwarding boundary
        return env
