from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional, Protocol, Tuple

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    EnvelopeFactory,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FlowFlags,
    SecureAcceptFrame,
    SecureOpenFrame,
    local_delivery_context,
    parse_address,
)
from naylence.fame.errors.errors import FameTransportClose
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.util import logging

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


PoolKey = Tuple[str, str]


class ResolveAddressByCapability(Protocol):
    async def __call__(self, capabilities: List[str]) -> Optional[FameAddress]: ...


class RoutingAction(ABC):
    @abstractmethod
    async def execute(
        self,
        envelope: FameEnvelope,
        router: RoutingNodeLike,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ):
        pass


class Drop(RoutingAction):
    async def execute(
        self,
        envelope: FameEnvelope,
        router: RoutingNodeLike,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ):
        """
        When an ordinary Data envelope is unroutable we now bounce a single
        **NACK** (DeliveryAckFrame) back toward the sender, provided the
        original envelope carries an `id` *and* a `reply_to` address.  This
        gives the caller deterministic, < RTT feedback instead of a long RPC
        timeout.  We mark the bounced envelope `reset=True` to prevent loops.
        """

        await emit_delivery_nack(envelope, router, state, code="NO_ROUTE", context=context)

        logger.debug("dropped_envelope", **logging.summarize_env(envelope, prefix=""))


class ForwardUp(RoutingAction):
    async def execute(
        self,
        envelope: FameEnvelope,
        router: RoutingNodeLike,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ):
        await router.forward_upstream(envelope, context)


class DeliverLocal(RoutingAction):
    def __init__(self, recipient_name: FameAddress):
        self.recipient_name = recipient_name

    async def execute(
        self,
        envelope: FameEnvelope,
        router: RoutingNodeLike,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ):
        await router.deliver_local(self.recipient_name, envelope, context)


class ForwardChild(RoutingAction):
    def __init__(self, segment: str):
        self.segment = segment

    async def execute(
        self,
        envelope: FameEnvelope,
        router: RoutingNodeLike,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ):
        try:
            await router.forward_to_route(self.segment, envelope, context)
        except FameTransportClose:
            logger.error("transport_closed", exc_info=True)
            await router.remove_downstream_route(self.segment)
            if not isinstance(envelope.frame, DeliveryAckFrame):
                await emit_delivery_nack(
                    envelope=envelope,
                    routing_node=router,
                    state=state,
                    code="ROUTE_CONNECTOR_CLOSED",
                    context=context,
                )


class ForwardPeer(RoutingAction):
    def __init__(self, segment: str):
        self.segment = segment

    async def execute(
        self,
        envelope: FameEnvelope,
        router: RoutingNodeLike,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ):
        try:
            await router.forward_to_peer(self.segment, envelope, context)
        except FameTransportClose:
            logger.error("transport_closed", exc_info=True)
            await router.remove_peer_route(self.segment)
            if not isinstance(envelope.frame, DeliveryAckFrame):
                await emit_delivery_nack(
                    envelope=envelope,
                    routing_node=router,
                    state=state,
                    code="ROUTE_CONNECTOR_CLOSED",
                    context=context,
                )


class RouterState:
    def __init__(
        self,
        *,
        node_id: str,
        local: set[str],
        downstream_address_routes: dict[FameAddress, str],
        peer_address_routes: Optional[dict[FameAddress, str]] = None,
        child_segments: set[str],
        peer_segments: set[str],
        has_parent: bool,
        physical_segments: List[str],
        pools: dict[PoolKey, set[str]],
        capabilities: Optional[
            dict[str, dict[FameAddress, str]]
        ] = None,  # capability_name -> { address -> route}
        resolve_address_by_capability: Optional[ResolveAddressByCapability] = None,
        envelope_factory: Optional[EnvelopeFactory] = None,
    ):
        self.node_id = node_id
        self.local = local
        self.downstream_address_routes = downstream_address_routes
        self.peer_address_routes = peer_address_routes or {}
        self.child_segments = child_segments
        self.peer_segments = peer_segments
        self.has_parent = has_parent
        self.physical_segments = physical_segments
        self.capabilities = capabilities if capabilities is not None else {}
        self.pools = pools
        self.resolve_address_by_capability = resolve_address_by_capability
        self.envelope_factory = envelope_factory

    def next_hop(self, full_path: str) -> str | None:
        rel = strip_self_prefix(full_path, self.physical_segments)
        return rel[0] if rel else None


async def emit_delivery_nack(
    envelope: FameEnvelope,
    routing_node: RoutingNodeLike,
    state: RouterState,
    code: str,
    context: Optional[FameDeliveryContext] = None,
):
    target_addr = envelope.reply_to
    if (
        isinstance(envelope.frame, (DataFrame | SecureOpenFrame))
        and envelope.id
        and target_addr
        and envelope.corr_id
    ):
        logger.debug(
            "creating_nack",
            to=target_addr,
            corr_id=envelope.id,
            code=code,
            orig_env_id=envelope.id,
        )

        assert state.envelope_factory

        # Create appropriate NACK frame based on the original frame type
        if isinstance(envelope.frame, SecureOpenFrame):
            # For SecureOpenFrame, send back a SecureAcceptFrame with ok=False
            nack_frame = SecureAcceptFrame(
                cid=envelope.frame.cid,
                eph_pub=b"\x00" * 32,  # Dummy key for failed channel
                ok=False,
                ref_id=envelope.id,
                reason=f"Channel handshake failed: {code} - Unroutable to {envelope.to}",
                alg=envelope.frame.alg,
            )
        else:
            # For DataFrame and other frames, send regular DeliveryAckFrame
            nack_frame = DeliveryAckFrame(
                ok=False,
                code=code,
                ref_id=envelope.id,
                reason=f"Unroutable to {envelope.to}",
            )

        nack_env = state.envelope_factory.create_envelope(
            to=target_addr,
            frame=nack_frame,
            flags=FlowFlags.RESET,  # one bounce max
            corr_id=envelope.corr_id,
        )

        try:
            # 1️⃣  Local delivery?
            if target_addr in state.local:
                await routing_node.deliver_local(target_addr, nack_env, context)
            else:
                # 2️⃣  Downstream child?
                _, target_path = parse_address(target_addr)

                remainder = strip_self_prefix(target_path, state.physical_segments)
                first_seg = remainder[0] if remainder else None

                delivery_context = local_delivery_context(state.node_id)
                if first_seg and first_seg in state.child_segments:
                    await routing_node.forward_to_route(first_seg, nack_env, delivery_context)
                elif first_seg and first_seg in state.peer_segments:
                    await routing_node.forward_to_peer(first_seg, nack_env, delivery_context)
                else:
                    # 3️⃣  Default → upstream
                    await routing_node.forward_upstream(nack_env, delivery_context)
        except Exception as e:  # never let NACK crash routing
            logger.trace("nack_forward_failed", error=e)


def strip_self_prefix(path: str, self_segments: list[str]) -> list[str]:
    """
    "/R001/C873/abc"   with  self_segments=["R001"]   -> ["C873", "abc"]
    "/R001"            with  self_segments=["R001"]   -> []
    """
    segments = path.lstrip("/").split("/")
    if segments[: len(self_segments)] == self_segments:
        return segments[len(self_segments) :]
    return segments
