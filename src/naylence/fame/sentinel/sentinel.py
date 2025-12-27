from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, cast

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.core import (
    AddressBindFrame,
    AuthorizationContext,
    DeliveryOriginType,
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    FlowFlags,
    SecurityContext,
    create_resource,
    format_address,
    generate_id,
    local_delivery_context,
)
from naylence.fame.node.admission.node_attach_client import AttachInfo
from naylence.fame.node.binding_manager import SYSTEM_INBOX
from naylence.fame.node.node import DEFAULT_BINDING_ACK_TIMEOUT_MS, FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.node.upstream_session_manager import UpstreamSessionManager
from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.sentinel.address_bind_frame_handler import AddressBindFrameHandler
from naylence.fame.sentinel.capability_aware_routing_policy import (
    CapabilityAwareRoutingPolicy,
)
from naylence.fame.sentinel.capability_frame_handler import CapabilityFrameHandler
from naylence.fame.sentinel.composite_routing_policy import CompositeRoutingPolicy
from naylence.fame.sentinel.credit_update_frame_handler import CreditUpdateFrameHandler
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler
from naylence.fame.sentinel.node_heartbeat_frame_handler import (
    NodeHeartbeatFrameHandler,
)
from naylence.fame.sentinel.peer import Peer
from naylence.fame.sentinel.route_manager import AddressRouteInfo, RouteManager
from naylence.fame.sentinel.router import Drop, RouterState, RoutingAction
from naylence.fame.sentinel.routing_policy import RoutingPolicy
from naylence.fame.sentinel.store.route_store import RouteStore, get_default_route_store
from naylence.fame.stickiness.load_balancer_stickiness_manager import (
    LoadBalancerStickinessManager,
)
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.util.envelope_context import current_trace_id
from naylence.fame.util.logging import getLogger, summarize_env

logger = getLogger(__name__)

DEFAULT_ATTACH_TIMEOUT_SEC = 5


class Sentinel(FameNode, RoutingNodeLike):
    """A Fame node that can route frames to downstream connectors."""

    _ALLOWED_BEFORE_ATTACH = {"NodeAttach"}

    def __init__(
        self,
        *,
        route_store: Optional[RouteStore] = None,
        has_parent: bool = False,
        routing_policy: Optional[RoutingPolicy] = None,
        attach_timeout_sec: int = DEFAULT_ATTACH_TIMEOUT_SEC,
        max_attach_ttl_sec: Optional[int] = None,
        binding_ack_timeout_ms: int = DEFAULT_BINDING_ACK_TIMEOUT_MS,
        peers: Optional[list[Peer]] = None,
        event_listeners: Optional[list] = None,
        node_meta_store: Optional[InMemoryKVStore[NodeMeta]] = None,
        attachment_key_validator: Optional[AttachmentKeyValidator] = None,
        stickiness_manager: Optional[LoadBalancerStickinessManager] = None,
        **kwargs,
    ):
        # Ensure storage_provider is included in kwargs if not already present
        if "storage_provider" not in kwargs:
            # Create a default in-memory storage provider
            from naylence.fame.storage.in_memory_storage_provider import (
                InMemoryStorageProvider,
            )

            kwargs["storage_provider"] = InMemoryStorageProvider()

        # Provide default route store if none is provided
        if route_store is None:
            route_store = get_default_route_store()

        # Provide default node_meta_store if none is provided
        if node_meta_store is None:
            node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

        # Store the attachment key validator for use by frame handlers
        self._attachment_key_validator = attachment_key_validator

        # Pass node_security, event_listeners and other arguments to FameNode
        # FameNode will handle security setup including key_manager via SecurityManager
        super().__init__(
            has_parent=has_parent,
            binding_ack_timeout_ms=binding_ack_timeout_ms,
            event_listeners=event_listeners,
            node_meta_store=node_meta_store,
            **kwargs,
        )

        # Use authorizer from SecurityManager - no fallback needed
        # since SecurityManager handles default creation
        assert self._security_manager.authorizer
        if self._security_manager.authorizer is None:
            raise RuntimeError(
                "SecurityManager must provide an authorizer for Sentinel nodes. "
                "Check your security policy configuration."
            )

        self._route_manager = RouteManager(
            deliver=self.deliver,
            route_store=route_store,
        )

        self._routing_policy = routing_policy or CompositeRoutingPolicy(
            [CapabilityAwareRoutingPolicy(), HybridPathRoutingPolicy()]
        )

        self._node_attach_frame_handler = NodeAttachFrameHandler(
            routing_node=self,
            key_manager=self._security_manager.key_manager,
            route_manager=self._route_manager,
            attachment_key_validator=self._attachment_key_validator,
            stickiness_manager=stickiness_manager,
            max_ttl_sec=max_attach_ttl_sec,
        )

        self._node_heartbeat_frame_handler = NodeHeartbeatFrameHandler(
            routing_node=self,
        )

        self._address_bind_frame_handler = AddressBindFrameHandler(
            routing_node=self,
            route_manager=self._route_manager,
            upstream_connector=lambda: self._upstream_connector,
        )

        self._capability_frame_handler = CapabilityFrameHandler(
            routing_node=self,
            route_manager=self._route_manager,
            upstream_connector=lambda: self._upstream_connector,
        )

        self._credit_update_frame_handler = CreditUpdateFrameHandler(
            routing_node=self,
            route_manager=self._route_manager,
        )

        self._janitor_task: Optional[asyncio.Task] = None

        self._attach_timeout_sec = attach_timeout_sec

        self._peers: list[Peer] = peers or []
        self._peer_session_managers: dict[str, UpstreamSessionManager] = {}

        self._pending_binds: Dict[str, asyncio.Future[bool]] = {}
        self._ack_timeout_sec = binding_ack_timeout_ms / 1000.0

        self._pending_lock = asyncio.Lock()

        self._routing_epoch = generate_id()

    # ---------------------------------------------------------------------------------- properties

    @property
    def routing_epoch(self) -> str:
        """The current routing epoch for this sentinel node."""
        return self._routing_epoch

    # ---------------------------------------------------------------------------------- lifecycle

    async def start(self):
        await super().start()

        self._route_manager._stop_event.set()

        await self._route_manager.start()

        await self._connect_to_peers()

        self._route_manager._stop_event.clear()
        self._janitor_task = self.spawn(self._route_manager._janitor_loop(), name=f"janitor-{self.id}")

    async def stop(self):
        await self._route_manager.stop()
        await super().stop()

    # ---------------------------------------------------------------------------------- helpers
    def _maybe_forget_flow(self, envelope: FameEnvelope) -> None:
        fid = envelope.flow_id
        if not fid:
            return
        if envelope.flow_flags and (envelope.flow_flags & FlowFlags.RESET):  # or your FlowClose frame type
            self._route_manager._flow_routes.pop(fid, None)

    async def _dispatch_routing_action_selected(
        self,
        envelope: FameEnvelope,
        selected: RoutingAction,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[RoutingAction]:
        """
        Dispatch on_routing_action_selected event to all listeners.

        This provides a single, centralized hook for route authorization after
        the routing policy has selected an action but before it executes.

        Returns the final action to execute, or None to drop the envelope.
        """
        current_action = selected

        for listener in self._event_listeners:
            if hasattr(listener, "on_routing_action_selected"):
                method = getattr(listener, "on_routing_action_selected")
                try:
                    result = await method(self, envelope, current_action, state, context)
                    if result is None:
                        # Listener signaled to drop - return None
                        return None
                    current_action = result
                except Exception as e:
                    logger.warning(
                        "routing_action_selected_hook_failed",
                        listener=type(listener).__name__,
                        error=str(e),
                    )
                    # On hook failure, drop the envelope for safety
                    return None

        return current_action

    # ---------------------------------------------------------------------------------- public API

    async def create_origin_connector(
        self,
        *,
        origin_type: DeliveryOriginType,
        system_id: str,
        connector_config: ConnectorConfig,
        authorization: Optional[AuthorizationContext] = None,
        **kwargs: Any,
    ) -> FameConnector:
        """Factory helper invoked by the admission path."""

        connector: FameConnector = await create_resource(ConnectorFactory, connector_config, **kwargs)
        assert connector, "Connector creation failed"

        attached = asyncio.Event()
        buffer: list[FameEnvelope] = []  # non-handshake frames while unattached

        async def gated_handler(env: FameEnvelope, context: Optional[FameDeliveryContext] = None):
            security_context = None
            if context:
                assert not context.from_connector or connector == context.from_connector, (
                    "Context connector mismatch"
                )
                assert not context.from_system_id or system_id == context.from_system_id, (
                    "Context system_id mismatch"
                )
                assert not context.origin_type or origin_type == context.origin_type, (
                    "Context origin_type mismatch"
                )

                security_context = context.security

            if security_context is None:
                security_context = SecurityContext()

            security_context.authorization = authorization

            context_override = FameDeliveryContext(
                from_connector=connector,
                from_system_id=system_id,
                origin_type=origin_type,
                security=security_context,
            )

            await self._dispatch_envelope_event("on_envelope_received", self, env, context)

            if not attached.is_set():
                if env.frame.type in self._ALLOWED_BEFORE_ATTACH:
                    await self.deliver(env, context_override)
                else:
                    buffer.append(env)
                return

            # first delivery after attach: drain buffer atomically
            while buffer:
                pending = buffer.pop(0)
                await self.deliver(pending, context_override)
            # deliver current frame

            await self.deliver(env, context_override)

        await connector.start(gated_handler)

        self._route_manager._pending_routes[system_id] = (connector, attached, buffer)
        self._route_manager._pending_route_metadata[system_id] = connector_config
        return connector

    def child_for(self, addr: FameAddress) -> Optional[str]:
        route_info = self._route_manager._downstream_addresses_routes.get(addr)
        return route_info.segment if route_info else None

    def build_router_state(self) -> RouterState:
        # Convert enhanced routing info to legacy format for router state
        legacy_downstream_routes = {
            addr: info.segment for addr, info in self._route_manager._downstream_addresses_routes.items()
        }

        return RouterState(
            node_id=self.id,
            local=set(self._binding_manager.get_addresses()),
            downstream_address_routes=legacy_downstream_routes,
            peer_address_routes=self._route_manager._peer_addresses_routes,
            child_segments=set(self._route_manager.downstream_routes.keys()),
            peer_segments=set(self._route_manager._peer_routes.keys()),
            pools=self._address_bind_frame_handler.pools,
            has_parent=self._has_parent,
            physical_segments=self._physical_segments,
            capabilities=self._capability_frame_handler.cap_routes,
            resolve_address_by_capability=self._service_manager.resolve_address_by_capability,
            envelope_factory=self._envelope_factory,
        )

    def _is_attached(self, seg: str) -> bool:
        return seg in self._route_manager.downstream_routes  # registered via register_route()

    def _downstream_connector(self, system_id: str) -> Optional[FameConnector]:
        """Get downstream connector for a system_id/route."""
        return self._route_manager.downstream_routes.get(system_id)

    async def _on_epoch_change(self, epoch: str):
        await super()._on_epoch_change(epoch)
        await self._propagate_address_bindings_upstream(epoch)

    async def _propagate_address_bindings_upstream(self, epoch: str):
        if not self.has_parent:
            logger.warning("No upstream defined to rebind addresses")
            return

        logger.debug("propagating_address_routes_upstream")

        sem = asyncio.Semaphore(32)  # throttle burst to 32 in-flight

        async def _bind(address: FameAddress, address_route_info: AddressRouteInfo) -> None:
            async with sem:
                try:
                    logger.debug("rebinding_address_upstream", address=address)
                    await self._bind_address_upstream(
                        address,
                        address_route_info,
                        # force=True           # skip the “is it already bound?” check
                    )
                except Exception as e:
                    logger.error("rebind_failed", address=address, error=e, exc_info=True)

        await asyncio.gather(
            *(_bind(a, ari) for a, ari in self._route_manager._downstream_addresses_routes.items())
        )

        logger.debug(
            "propagating_address_routes_upstream_completed",
            count=len(self._route_manager._downstream_addresses_routes),
        )

    async def _bind_address_upstream(self, addr: FameAddress, address_route_info: AddressRouteInfo) -> None:
        """
        Send AddressBindFrame upstream and await the corresponding ACK.
        Raises on timeout or negative ACK.
        """
        corr_id = generate_id()
        fut = asyncio.get_event_loop().create_future()
        async with self._pending_lock:
            self._pending_binds[corr_id] = fut

        frame = AddressBindFrame(
            address=addr,
            physical_path=address_route_info.physical_path,
            encryption_key_id=address_route_info.encryption_key_id,
        )
        reply_to = format_address(SYSTEM_INBOX, self.physical_path)
        env = self._envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=frame,
            reply_to=reply_to,
            corr_id=corr_id,
        )
        await self.forward_upstream(env, local_delivery_context(self.id))

        try:
            ok = await asyncio.wait_for(fut, timeout=self._ack_timeout_sec)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout waiting for bind ack for {addr!r}")
        finally:
            async with self._pending_lock:
                self._pending_binds.pop(corr_id, None)

        if not ok:
            raise RuntimeError(f"Bind to {addr!r} was rejected")

    async def deliver(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        # Dispatch to all event listeners for security processing
        processed_envelope = await self._dispatch_envelope_event(
            "on_deliver", self, envelope, context=context
        )

        # If any listener returns None, halt delivery (security violation or envelope queued for keys)
        if processed_envelope is None:
            return

        frame_type = processed_envelope.frame.type

        if frame_type in [
            "AddressBindAck",
            "AddressUnbindAck",
            "CapabilityAdvertiseAck",
            "CapabilityWithdrawAck",
        ]:
            await self._delivery_tracker.on_envelope_delivered(SYSTEM_INBOX, envelope, context)
            return None

        if not context or context.origin_type != DeliveryOriginType.LOCAL:
            if frame_type == "NodeAttach":
                await self._node_attach_frame_handler.accept_node_attach(processed_envelope, context)
            elif frame_type == "AddressBind":
                await self._address_bind_frame_handler.accept_address_bind(processed_envelope, context)
            elif frame_type == "AddressUnbind":
                await self._address_bind_frame_handler.accept_address_unbind(processed_envelope, context)
            elif frame_type == "CapabilityAdvertise":
                await self._capability_frame_handler.accept_capability_advertise(
                    processed_envelope, context
                )
            elif frame_type == "CapabilityWithdraw":
                await self._capability_frame_handler.accept_capability_withdraw(processed_envelope, context)
            elif frame_type == "CreditUpdate":
                await self._credit_update_frame_handler.accept_credit_update(processed_envelope, context)
            elif frame_type == "NodeHeartbeat":
                await self._node_heartbeat_frame_handler.accept_node_heartbeat(processed_envelope, context)

        # Note: KeyAnnounce and KeyRequest frames are now handled by SecurityManager.on_deliver

        state = self.build_router_state()
        selected_action: RoutingAction = await self._routing_policy.decide(
            processed_envelope, state, context
        )

        # Dispatch on_routing_action_selected hook for route authorization
        # This allows security managers and other listeners to authorize or replace
        # the selected action before it executes
        action = await self._dispatch_routing_action_selected(
            processed_envelope, selected_action, state, context
        )

        if action is None:
            # Hook signaled to drop - use Drop action with NO_ROUTE nack
            action = Drop()

        await action.execute(processed_envelope, self, state, context)

    async def forward_to_route(
        self,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        if self._origin_matches(context, next_segment, DeliveryOriginType.DOWNSTREAM):
            # Don't forward envelopes that originated from the same downstream route to avoid loops
            logger.debug("downstream_loop_detected", envp_id=envelope.id, segment=next_segment)

        processed_envelope: Optional[FameEnvelope] = None

        try:
            # Dispatch to all event listeners for security processing
            processed_envelope = await self._dispatch_envelope_event(
                "on_forward_to_route", self, next_segment, envelope, context=context
            )
            # If any listener returns None, halt forwarding (envelope queued for keys)
            if processed_envelope is None:
                return

            # Downstream routes may disappear at any time (child crashed / detached).
            # Treat that as a normal run-time event: inform the sender instead of
            # crashing the receive-loop, mirroring the peer-handling logic.
            logger.debug(
                "forwarding_downstream",
                **summarize_env(processed_envelope, prefix=""),
                route=next_segment,
            )
            conn = self._route_manager.downstream_routes.get(next_segment)
            if not conn:
                logger.warning("no_route_for_child_segment", segment=next_segment)
                await self.emit_delivery_nack(processed_envelope, code="CHILD_UNREACHABLE", context=context)
                return
            await conn.send(processed_envelope)

            fid = processed_envelope.flow_id
            if fid and fid not in self._route_manager._flow_routes:
                self._route_manager._flow_routes[fid] = conn

            self._maybe_forget_flow(processed_envelope)
        except Exception as e:
            # Capture the exception for the completion event
            await self._dispatch_envelope_event(
                "on_forward_to_route_complete",
                self,
                next_segment,
                processed_envelope or envelope,
                error=e,
                context=context,
            )
            # Re-raise the original exception
            raise
        else:
            # No exception occurred - call completion event without error
            await self._dispatch_envelope_event(
                "on_forward_to_route_complete",
                self,
                next_segment,
                processed_envelope or envelope,
                context=context,
            )

    async def forward_to_peer(
        self,
        peer_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        if self._origin_matches(context, peer_segment, DeliveryOriginType.PEER):
            # Don't forward envelopes that originated from the same downstream route to avoid loops
            logger.debug("downstream_loop_detected", envp_id=envelope.id, segment=peer_segment)

        # Dispatch to all event listeners for security processing
        processed_envelope = await self._dispatch_envelope_event(
            "on_forward_to_peer", self, peer_segment, envelope, context=context
        )

        # If any listener returns None, halt forwarding (envelope queued for keys)
        if processed_envelope is None:
            return

        logger.debug(
            "forwarding_to_peer",
            **summarize_env(processed_envelope, prefix=""),
            route=peer_segment,
        )
        conn = self._route_manager._peer_routes.get(peer_segment)
        if not conn:
            # Instead of crashing, emit a NACK so the client gets immediate feedback
            logger.warning("no_route_for_peer_segment", peer_segment=peer_segment)
            await self.emit_delivery_nack(processed_envelope, code="PEER_UNREACHABLE", context=context)
            return

        await conn.send(processed_envelope)

        await self._dispatch_envelope_event(
            "on_forward_to_peer_complete", self, peer_segment, envelope, context=context
        )

        fid = processed_envelope.flow_id
        if fid and fid not in self._route_manager._flow_routes:
            self._route_manager._flow_routes[fid] = conn

        self._maybe_forget_flow(processed_envelope)

    async def forward_to_peers(
        self,
        envelope: FameEnvelope,
        peers: Optional[list[str]] = None,
        exclude_peers: Optional[list[str]] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        # Dispatch to all event listeners for security processing
        processed_envelope = await self._dispatch_envelope_event(
            "on_forward_to_peers", self, envelope, peers, exclude_peers, context=context
        )

        # If any listener returns None, halt forwarding (envelope queued for keys)
        if processed_envelope is None:
            return

        logger.debug(
            "forwarding_to_peers",
            **summarize_env(processed_envelope, prefix=""),
            peers=peers,
            exclude_peers=exclude_peers,
        )
        # Start with all available peers or the specific peers requested
        available_peers = set(peers or self._route_manager._peer_routes.keys())

        # Remove any excluded peers
        if exclude_peers:
            available_peers = available_peers - set(exclude_peers)

        for peer_id in available_peers:
            conn = self._route_manager._peer_routes.get(peer_id)
            if not conn:
                raise RuntimeError(f"No route for peer segment '{peer_id}'")

            processed_envelope = await self._dispatch_envelope_event(
                "on_forward_to_peer", self, peer_id, envelope, context=context
            )
            if processed_envelope is None:
                continue

            await conn.send(processed_envelope)

            await self._dispatch_envelope_event(
                "on_forward_to_peer_complete", self, peer_id, envelope, context=context
            )

            fid = processed_envelope.flow_id
            if fid and fid not in self._route_manager._flow_routes:
                self._route_manager._flow_routes[fid] = conn

            self._maybe_forget_flow(processed_envelope)

    async def forward_upstream(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None:
        if context and context.origin_type == DeliveryOriginType.UPSTREAM:
            # Don't forward envelopes that originated from upstream to avoid loops
            logger.debug(
                "skipping_forward_upstream",
                envp_id=envelope.id,
                origin_type=context.origin_type,
            )
            return

        await super().forward_upstream(envelope, context)
        if not self._upstream_connector:
            return
        fid = envelope.flow_id
        if fid and fid not in self._route_manager._flow_routes:
            self._route_manager._flow_routes[fid] = self._upstream_connector  # remember parent
        self._maybe_forget_flow(envelope)

    async def _connect_to_peer(self, peer: Peer):
        if not self.attach_client:
            raise RuntimeError("Missing attach client")

        if not peer.admission_client:
            raise RuntimeError("Missing admission client")

        # if peer.system_id in self._route_manager.downstream_routes:
        #     raise RuntimeError(f"Peer segment {peer.system_id} exist in downstream routes")

        peer_session_manager = UpstreamSessionManager(
            node=self,
            outbound_origin_type=DeliveryOriginType.PEER,
            inbound_origin_type=DeliveryOriginType.PEER,
            admission_client=peer.admission_client,
            attach_client=self.attach_client,
            # connector_factory=self.connector_factory,
            requested_logicals=[],
            inbound_handler=self.handle_inbound_from_peer,
            on_attach=self._on_node_attach_to_peer,
            on_epoch_change=self._on_epoch_change,
            on_welcome=self._on_welcome,
            retry_policy=self._connection_retry_policy,
        )
        await peer_session_manager.start()
        assert peer_session_manager.system_id

        self._peer_session_managers[peer_session_manager.system_id] = peer_session_manager
        self._route_manager._peer_routes[peer_session_manager.system_id] = cast(
            FameConnector, peer_session_manager
        )

    async def _on_node_attach_to_peer(self, info: AttachInfo, connector: FameConnector):
        # Dispatch peer attachment event to all listeners
        await self._dispatch_event("on_node_attach_to_peer", self, info, connector)

    async def handle_inbound_from_peer(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ) -> None:
        assert context
        context.origin_type = DeliveryOriginType.PEER
        await self.deliver(envelope, context=context)

    async def _connect_to_peers(self):
        # Create a list to track peer connection tasks
        connect_tasks = []
        for peer in self._peers:
            task = self.spawn(self._connect_to_peer(peer), name=f"peer-{id(peer)}")
            connect_tasks.append(task)

        # Wait for all tasks to complete and handle any exceptions
        if connect_tasks:
            done, _ = await asyncio.wait(connect_tasks, return_when=asyncio.ALL_COMPLETED)
            for task in done:
                exc = task.exception()
                if exc:
                    # Re-raise the exception to prevent silent failures
                    raise exc

    async def _delayed_connector_cleanup(self, connector: FameConnector, delay: float) -> None:
        """
        Wait for the specified delay before stopping the connector.
        This allows in-flight messages (like NACKs) to be sent before shutting down.
        """
        try:
            await asyncio.sleep(delay)
            await self._route_manager._safe_stop(connector)
            logger.debug("delayed_connector_cleanup_completed")
        except Exception as e:
            logger.error("delayed_connector_cleanup_failed", error=e, exc_info=True)

    async def emit_delivery_nack(
        self,
        envelope: FameEnvelope,
        *,
        code: str,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        """Helper to emit a delivery NACK for an undeliverable envelope."""
        from naylence.fame.sentinel.router import emit_delivery_nack

        state = self.build_router_state()
        await emit_delivery_nack(envelope, self, state, code, context)

    async def resolve_encryption_key_for_address(self, target_address: FameAddress) -> Optional[str]:
        """Resolve the encryption key ID for a target address when needed."""
        route_info = self._route_manager._downstream_addresses_routes.get(target_address)
        if not route_info:
            # Try peer routes
            segment = self._route_manager._peer_addresses_routes.get(target_address)
            if not segment:
                return None
            # For peers, we'd need to implement similar resolution
            return None

        # Query key manager for encryption keys associated with this segment's physical path
        # This will be implemented when the security policy needs to encrypt
        return None  # TODO: Implement when needed

    async def remove_downstream_route(self, segment: str, *, stop: bool = True):
        return await self._route_manager._remove_downstream_route(segment, stop=stop)

    async def remove_peer_route(self, segment: str, *, stop: bool = True):
        return await self._route_manager._remove_peer_route(segment, stop=stop)

    def _origin_matches(
        self,
        context: Optional[FameDeliveryContext],
        segment: str,
        origin_type: DeliveryOriginType = DeliveryOriginType.DOWNSTREAM,
    ) -> bool:
        """
        Returns True if the message originated from the segment
        """
        return (
            context is not None and context.origin_type == origin_type and context.from_system_id == segment
        )

    @staticmethod
    async def aserve(
        *,
        log_level: str | int | None = None,
        **kwargs,
    ):
        stop_evt = asyncio.Event()
        loop = asyncio.get_running_loop()

        import signal

        from naylence.fame.core import FameFabric
        from naylence.fame.util.logging import enable_logging

        enable_logging(log_level=log_level)  # type: ignore

        loop.add_signal_handler(signal.SIGINT, stop_evt.set)
        loop.add_signal_handler(signal.SIGTERM, stop_evt.set)

        async with FameFabric.get_or_create(**kwargs):
            logger.info("Node is live!  Press Ctrl+C to stop.")
            await stop_evt.wait()
            logger.info("⏳ Shutting down…")
