from __future__ import annotations

import asyncio
from contextvars import ContextVar
from datetime import datetime
from typing import TYPE_CHECKING, Any, AsyncIterator, Awaitable, Callable, List, Optional

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.delivery_tracker import DeliveryTracker
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.node.node_meta import NodeMeta

if TYPE_CHECKING:
    from naylence.fame.security.security_manager import SecurityManager
    from naylence.fame.storage.storage_provider import StorageProvider

from naylence.fame.core import (
    DEFAULT_INVOKE_TIMEOUT_MILLIS,
    DEFAULT_POLLING_TIMEOUT_MS,
    Binding,
    DeliveryAckFrame,
    DeliveryOriginType,
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    FameResponseType,
    FameRPCHandler,
    NodeWelcomeFrame,
    create_channel_message,
    format_address,
    generate_id,
)
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.node_attach_client import (
    AttachInfo,
    NodeAttachClient,
)
from naylence.fame.node.binding_manager import BindingManager, BindingStoreEntry
from naylence.fame.node.connection_retry_policy import ConnectionRetryPolicy
from naylence.fame.node.envelope_listener_manager import EnvelopeListenerManager
from naylence.fame.node.node_envelope_factory import (
    EnvelopeFactory,
    NodeEnvelopeFactory,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.node.root_session_manager import RootSessionManager
from naylence.fame.node.session_manager import SessionManager
from naylence.fame.node.upstream_session_manager import UpstreamSessionManager
from naylence.fame.service.default_service_manager import DefaultServiceManager
from naylence.fame.service.service_manager import ServiceManager
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.util.logging import getLogger, summarize_env
from naylence.fame.util.task_spawner import TaskSpawner
from naylence.fame.util.util import secure_digest

logger = getLogger(__name__)

SYSTEM_INBOX = "__sys__"

DEFAULT_BINDING_ACK_TIMEOUT_MS = 20000


class FameEnvironmentContext:
    """Placeholder for Fame system context (e.g., metrics, tracing, etc.)"""

    pass


_NODE_STACK: ContextVar[Optional[List[FameNode]]] = ContextVar("_node_stack", default=None)


def get_node() -> FameNode:
    stack = _NODE_STACK.get()
    if not stack:
        raise RuntimeError("No FameNode in context")
    return stack[-1]


class _DefaultRetryHandler(RetryEventHandler):
    def __init__(
        self, delivery_fn: Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[Any]]
    ) -> None:
        super().__init__()
        self._delivery_fn = delivery_fn

    async def on_retry_needed(
        self,
        envelope: FameEnvelope,
        attempt: int,
        next_delay_ms: int,
        context: Optional[FameDeliveryContext] = None,
    ):
        logger.debug(
            "retrying_sending_envelope",
            envp_id=envelope.id,
            attempt=attempt,
            delay_ms=next_delay_ms,
        )
        await self._delivery_fn(envelope, context)


class FameNode(TaskSpawner, NodeLike):
    def __init__(
        self,
        *,
        node_meta_store: KeyValueStore[NodeMeta],
        system_id: Optional[str] = None,
        admission_client: Optional[AdmissionClient] = None,
        attach_client: Optional[NodeAttachClient] = None,
        has_parent: Optional[bool] = False,
        requested_logicals: Optional[List[str]] = None,
        env_context: Optional[Any] = None,
        binding_store: Optional[KeyValueStore[BindingStoreEntry]] = None,
        binding_factory: Optional[Callable[[FameAddress], Binding]] = None,
        service_manager: Optional[ServiceManager] = None,
        service_configs: Optional[List[Any]] = None,
        binding_ack_timeout_ms: int = DEFAULT_BINDING_ACK_TIMEOUT_MS,
        security_manager: Optional[SecurityManager] = None,
        event_listeners: Optional[List[NodeEventListener]] = None,
        public_url: Optional[str] = None,
        storage_provider: StorageProvider,
        delivery_tracker: DeliveryTracker,
        delivery_policy: Optional[DeliveryPolicy] = None,
        connection_retry_policy: Optional[ConnectionRetryPolicy] = None,
        **kwargs: Any,
    ):
        TaskSpawner.__init__(self)

        self._node_meta_store = node_meta_store

        # ------------------------------------------------------------------ #
        # Initialize event listeners system                                  #
        # ------------------------------------------------------------------ #
        self._event_listeners: List[NodeEventListener] = []

        # Add event listeners from parameter
        if event_listeners:
            self._event_listeners.extend(event_listeners)

        class WelcomeHandler(NodeEventListener):
            def __init__(self, node: FameNode):
                self._node = node

            async def on_welcome(self, welcome_frame: NodeWelcomeFrame) -> None:
                if welcome_frame.system_id:
                    logger.debug(
                        "setting_provisional_system_id",
                        system_id=welcome_frame.system_id,
                    )
                    self._node._id = welcome_frame.system_id

        self._event_listeners.append(WelcomeHandler(self))

        # ------------------------------------------------------------------ #
        # determine security bundle                                          #
        # ------------------------------------------------------------------ #
        if security_manager is None:
            # fall back to no security manager by default
            from naylence.fame.security.no_security_manager import NoSecurityManager

            security_manager = NoSecurityManager()

        # Store the SecurityManager for backwards compatibility and event dispatch
        self._security_manager = security_manager

        # Add security manager as an event listener
        self._event_listeners.append(security_manager)
        # ------------------------------------------------------------------ #

        self._id = system_id or ""
        self._sid = None  # secure source id to be used in envelopes
        self._admission_client = admission_client
        self.attach_client = attach_client
        self._has_parent = bool(has_parent)
        self._upstream_connector = None
        self._requested_logicals = requested_logicals or []
        self.fame_environment = env_context
        self._public_url = public_url
        self._storage_provider = storage_provider

        self._envelope_factory = NodeEnvelopeFactory(
            physical_path_fn=lambda: self.physical_path,
            sid_fn=lambda: self.sid,
        )

        self._physical_path = None
        self._physical_segments: list[str] = []
        if self._has_parent:
            self._handshake_completed = False
        else:
            self._handshake_completed = True

        self._accepted_logicals: set[str] = set()
        self._attach_expires_at: Optional[datetime] = None
        self._welcome_expires_at: Optional[datetime] = None

        self._delivery_tracker = delivery_tracker

        self._delivery_policy = delivery_policy
        self._connection_retry_policy = connection_retry_policy

        self._binding_manager = BindingManager(
            has_upstream=self._has_parent,
            get_id=lambda: self.id,
            get_sid=lambda: self.sid,
            get_physical_path=lambda: self.physical_path,
            get_accepted_logicals=lambda: self._accepted_logicals,
            get_encryption_key_id=lambda: self._security_manager.get_encryption_key_id(),
            forward_upstream=self.forward_upstream,
            binding_store=binding_store,
            binding_factory=binding_factory,
            envelope_factory=self._envelope_factory,
            ack_timeout_ms=binding_ack_timeout_ms,
            delivery_tracker=delivery_tracker,
        )

        self._envelope_listener_manager = EnvelopeListenerManager(
            binding_manager=self._binding_manager,
            node_like=self,
            # get_physical_path=lambda: self.physical_path,
            # get_id=lambda: self.id,
            # get_sid=lambda: self.sid,
            # deliver=deliver_fn,
            envelope_factory=self.envelope_factory,
            delivery_tracker=delivery_tracker,
        )

        self._service_manager = service_manager or DefaultServiceManager(
            invoke=self.invoke,
            serve_rpc=self._envelope_listener_manager.listen_rpc,
            serve=self._envelope_listener_manager.listen,
            default_service_configs=service_configs,
        )

        self._session_manager: Optional[SessionManager] = None

        # ------------------------------------------------------------------ #
        # Sort event listeners by priority                                   #
        # ------------------------------------------------------------------ #
        # Sort by priority (lower values = higher priority), with original
        # index as secondary sort key to maintain stable ordering for listeners
        # with the same priority
        self._sort_event_listeners()

        self._is_started = False

    @property
    def has_parent(self) -> bool:
        return self._has_parent  # self._upstream_connector is not None

    @property
    def physical_path(self) -> str:
        if not self._physical_path:
            raise RuntimeError("Physical path not assigned yet")
        return self._physical_path

    @property
    def default_binding_path(self) -> str:
        return self.physical_path

    @property
    def id(self) -> str:
        return self._id

    @property
    def sid(self) -> str:
        if not self._sid:
            raise RuntimeError("SID not assigned yet")
        return self._sid

    @property
    def accepted_logicals(self) -> set[str]:
        """Get the set of accepted logicals for this node."""
        return self._accepted_logicals

    @property
    def envelope_factory(self) -> EnvelopeFactory:
        return self._envelope_factory

    @property
    def security_manager(self) -> Optional[SecurityManager]:
        """The security manager for this node."""
        return self._security_manager

    @property
    def admission_client(self) -> Optional[AdmissionClient]:
        return self._admission_client

    @property
    def event_listeners(self) -> List[NodeEventListener]:
        """Get the list of event listeners for this node."""
        return self._event_listeners.copy()

    @property
    def public_url(self) -> Optional[str]:
        """Get the public URL for this node."""
        return self._public_url

    @property
    def storage_provider(self) -> StorageProvider:
        """Get the storage provider for this node."""
        return self._storage_provider

    @property
    def delivery_policy(self) -> Optional[DeliveryPolicy]:
        """Get the delivery policy for this node."""
        return self._delivery_policy

    def add_event_listener(self, listener: NodeEventListener) -> None:
        """Add an event listener to this node and maintain priority ordering."""
        if listener not in self._event_listeners:
            self._event_listeners.append(listener)
            # Re-sort to maintain priority ordering
            self._sort_event_listeners()

    def remove_event_listener(self, listener: NodeEventListener) -> None:
        """Remove an event listener from this node."""
        if listener in self._event_listeners:
            self._event_listeners.remove(listener)

    def _sort_event_listeners(self) -> None:
        """Sort event listeners by priority, maintaining stable ordering for equal priorities."""
        listeners_with_indices = list(enumerate(self._event_listeners))
        listeners_with_indices.sort(key=lambda item: (item[1].priority, item[0]))
        self._event_listeners = [listener for _, listener in listeners_with_indices]

    def gather_supported_callback_grants(self) -> list[dict[str, Any]]:
        """
        Gather supported inbound connectors from all active transport listeners.

        Returns:
            List of connector configurations that can be used for reverse connections
        """
        result = []

        from naylence.fame.connector.transport_listener import TransportListener

        for listener in self._event_listeners:
            if isinstance(listener, TransportListener):
                try:
                    connector_config = listener.as_callback_grant()
                    if connector_config:
                        result.append(connector_config)
                except Exception:
                    # Skip listeners that don't support inbound connectors
                    continue
        return result

    # ------------------------------------------------------------------ #
    # Event dispatching helpers                                          #
    # ------------------------------------------------------------------ #

    async def _dispatch_event(self, event_name: str, *args, **kwargs) -> None:
        """Dispatch a simple event to all listeners."""
        for listener in self._event_listeners:
            if hasattr(listener, event_name):
                method = getattr(listener, event_name)
                await method(*args, **kwargs)

    async def _dispatch_envelope_event(self, event_name: str, *args, **kwargs) -> Optional[FameEnvelope]:
        """
        Dispatch an envelope-processing event to all listeners.

        For events that return Optional[FameEnvelope], we iterate through listeners
        and stop processing if any listener returns None (halt signal).

        Returns the final processed envelope or None if processing should halt.
        """
        # Find the envelope in the arguments
        envelope = None
        envelope_arg_idx = None

        # Check kwargs first
        if "envelope" in kwargs:
            envelope = kwargs["envelope"]
        else:
            # Look for envelope in positional args - typically it's the second argument after 'self'
            for i, arg in enumerate(args):
                if hasattr(arg, "frame"):  # Simple duck-typing check for FameEnvelope
                    envelope = arg
                    envelope_arg_idx = i
                    break

        if envelope is None:
            raise ValueError(f"No envelope found in {event_name} call")

        current_envelope = envelope

        for listener in self._event_listeners:
            if hasattr(listener, event_name):
                method = getattr(listener, event_name)

                # Update envelope in kwargs or args for next listener
                if "envelope" in kwargs:
                    kwargs["envelope"] = current_envelope
                elif envelope_arg_idx is not None:
                    # Update positional args
                    args_list = list(args)
                    args_list[envelope_arg_idx] = current_envelope
                    args = tuple(args_list)

                result = await method(*args, **kwargs)

                # If any listener returns None, halt processing
                if result is None:
                    return None

                current_envelope = result

        return current_envelope

    async def start(self) -> None:
        if self._is_started:
            raise RuntimeError("Node already started")

        # Dispatch node initialized event first to set up cross-component dependencies
        await self._dispatch_event("on_node_initialized", self)

        if self._has_parent:
            await self._connect_to_upstream()
            self._sid = secure_digest(self.physical_path)
        else:
            await self._connect_root()
            self._sid = secure_digest(self.physical_path)

        node_meta = await self._node_meta_store.get("self")
        if node_meta is None:
            node_meta = NodeMeta(id=self._id)
        else:
            node_meta.id = self._id
        await self._node_meta_store.set("self", node_meta)

        # Begin normal operation
        await self.listen(SYSTEM_INBOX, self.handle_system_frame)
        await self._service_manager.start()

        # Dispatch node started event to all listeners for clean initialization
        await self._dispatch_event("on_node_started", self)

        # Restore bindings only after the node is fully started
        await self._binding_manager.restore()

        await self._envelope_listener_manager.start()

        self._is_started = True

        logger.info(
            "node_started",
            node_id=self.id,
            sid=self.sid,
            path=self._physical_path,
            logicals=self._accepted_logicals,
        )

    async def _connect_to_upstream(self):
        if not self.attach_client:
            raise RuntimeError("Missing attach client")
        if not self._admission_client:
            raise RuntimeError("Missing admission client")

        self._session_manager = UpstreamSessionManager(
            node=self,
            outbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_origin_type=DeliveryOriginType.UPSTREAM,
            attach_client=self.attach_client,
            requested_logicals=self._requested_logicals,
            inbound_handler=self.handle_inbound_from_upstream,
            on_welcome=self._on_welcome,
            on_attach=self._on_attach_to_upstream,
            on_epoch_change=self._on_epoch_change,
            admission_client=self._admission_client,
            retry_policy=self._connection_retry_policy,
        )
        await self._session_manager.start()

    async def _connect_root(self):
        # For root nodes, create a no-op admission client if none provided
        admission_client = self._admission_client
        if not admission_client:
            # Use proper NoopAdmissionClient for root nodes without admission service
            from naylence.fame.node.admission.noop_admission_client import NoopAdmissionClient

            admission_client = NoopAdmissionClient(
                system_id="root-system",
                auto_accept_logicals=True,
            )

        self._session_manager = RootSessionManager(
            node=self,
            admission_client=admission_client,
            requested_logicals=self._requested_logicals,
            on_welcome=self._on_welcome,
            on_epoch_change=self._on_epoch_change,
            # on_admission_failed=self._on_admission_failed,
        )
        await self._session_manager.start()

    @property
    def upstream_connector(self) -> Optional[FameConnector]:
        if self._session_manager and isinstance(self._session_manager, UpstreamSessionManager):
            return self._session_manager._connector
        return None

    async def _on_welcome(self, welcome_frame: NodeWelcomeFrame):
        self._id = welcome_frame.system_id
        self._accepted_logicals = set(welcome_frame.accepted_logicals or [])
        self._welcome_expires_at = welcome_frame.expires_at

        if not self._has_parent:
            if welcome_frame.assigned_path:
                self._physical_path = welcome_frame.assigned_path
                assert self._physical_path == f"/{welcome_frame.system_id}"
            else:
                self._physical_path = f"/{welcome_frame.system_id}"

            parts = self._physical_path.strip("/").split("/")
            self._physical_segments = parts if parts != [""] else []

            self._upstream_connector = None
            self._handshake_completed = True

        # Dispatch attach event to all listeners for parent-specific setup
        await self._dispatch_event("on_welcome", welcome_frame)

    async def _on_attach_to_upstream(self, info: AttachInfo, connector: FameConnector):
        assert self._id == info["system_id"]
        self._id = info["system_id"]
        self._physical_path = info["assigned_path"]
        parts = self._physical_path.strip("/").split("/")
        self._physical_segments = parts if parts != [""] else []
        self._accepted_logicals = set(info.get("accepted_logicals") or [])
        self._attach_expires_at = info.get("attach_expires_at")
        self._handshake_completed = True
        self._upstream_connector = connector

        # Assign the SID now that we have the physical path
        self._sid = secure_digest(self.physical_path)

        # Dispatch attach event to all listeners for parent-specific setup
        await self._dispatch_event("on_node_attach_to_upstream", self, info)

    async def _on_epoch_change(self, epoch: str):
        logger.debug("handle_epoch_change", epoch=epoch)
        await self._binding_manager.rebind_addresses_upstream()
        await self._binding_manager.readvertise_capabilities_upstream()

        # Dispatch epoch change event to all listeners
        await self._dispatch_event("on_epoch_change", self, epoch)

    async def stop(self) -> None:
        await self._dispatch_event("on_node_preparing_to_stop", self)
        await self.shutdown_tasks(grace_period=0.01)
        await self._envelope_listener_manager.stop()

        # if self._upstream_connector:
        #     await self._upstream_connector.stop()
        #     self._upstream_connector = None

        if self._session_manager:
            await self._session_manager.stop()

        await self._service_manager.stop()

        # if self._session_manager:
        #     await self._session_manager.stop()

        # Dispatch node stopped event to all listeners for clean shutdown
        await self._dispatch_event("on_node_stopped", self)

        self._is_started = False

    async def __aenter__(self):
        # ② push self onto the node‐stack before/during startup
        stack = _NODE_STACK.get()
        if stack is None:
            stack = []
        # we store the token on the instance so __aexit__ can reset()
        self._node_token = _NODE_STACK.set(stack + [self])

        # now carry on with your existing startup
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # first stop the node as you already do
        await self.stop()

        # ③ pop ourselves off the stack
        _NODE_STACK.reset(self._node_token)

        # re‐raise any errors
        return False

    async def handle_inbound_from_upstream(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ) -> None:
        await self.deliver(envelope, context=context)

    async def handle_system_frame(self, envelope: FameEnvelope, context: Optional[Any] = None):
        frame = envelope.frame

        logger.debug("processing_system_frame", frame_type=repr(frame.type))

        if frame.type == "NodeHeartbeat":
            self._last_heartbeat_at = asyncio.get_event_loop().time()
        elif frame.type == "DeliveryAck":
            # Handle NACK responses from policy violations
            logger.debug("handling_delivery_ack", **summarize_env(envelope, prefix=""))
            await self._handle_delivery_ack(envelope, context)
        else:
            logger.warning("handling_unknown_system_frame_type", frame_type=repr(frame.type))

    @property
    def binding_manager(self) -> BindingManager:
        return self._binding_manager

    async def bind(self, participant: str) -> Binding:
        return await self._binding_manager.bind(participant)

    async def unbind(self, participant: str) -> None:
        return await self._binding_manager.unbind(participant)

    async def listen(
        self,
        recipient: str,
        handler: FameEnvelopeHandler,
        poll_timeout_ms: Optional[int] = DEFAULT_POLLING_TIMEOUT_MS,
    ) -> FameAddress:
        return await self._envelope_listener_manager.listen(
            service_name=recipient, handler=handler, poll_timeout_ms=poll_timeout_ms
        )

    async def listen_rpc(
        self,
        service_name: str,
        handler: FameRPCHandler,
        poll_timeout_ms: int = DEFAULT_POLLING_TIMEOUT_MS,
    ) -> FameAddress:
        return await self._envelope_listener_manager.listen_rpc(
            service_name=service_name, handler=handler, poll_timeout_ms=poll_timeout_ms
        )

    async def invoke(
        self,
        target_addr: FameAddress,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> Any:
        return await self._envelope_listener_manager.invoke(
            target_addr=target_addr, method=method, params=params, timeout_ms=timeout_ms
        )

    async def invoke_by_capability(
        self,
        capabilities: list[str],
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> Any:
        return await self._envelope_listener_manager.invoke(
            capabilities=capabilities,
            method=method,
            params=params,
            timeout_ms=timeout_ms,
        )

    async def invoke_stream(
        self,
        target_addr: FameAddress,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> AsyncIterator[Any]:
        return self._envelope_listener_manager.invoke_stream(
            target_addr=target_addr, method=method, params=params, timeout_ms=timeout_ms
        )

    async def invoke_by_capability_stream(
        self,
        capabilities: list[str],
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> AsyncIterator[Any]:
        return self._envelope_listener_manager.invoke_stream(
            capabilities=capabilities,
            method=method,
            params=params,
            timeout_ms=timeout_ms,
        )

    async def deliver_local(
        self,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> None:
        # Dispatch to all event listeners for security processing
        processed_envelope = await self._dispatch_envelope_event(
            "on_deliver_local", self, address, envelope, context=context
        )

        # If any listener returns None, halt delivery (security violation or handled by frame handler)
        if processed_envelope is None:
            return

        # Send directly to the channel associated with the address, preserving context
        logger.debug("deliver_local", **summarize_env(processed_envelope, prefix=""))
        binding = self._binding_manager.get_binding(address)
        if not binding:
            raise RuntimeError(f"No local binding for address '{address}'")

        # Create channel message that preserves delivery context

        channel_message = create_channel_message(processed_envelope, context)
        await binding.channel.send(channel_message)

        await self._dispatch_envelope_event(
            "on_deliver_local_complete", self, address, envelope, context=context
        )

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

        logger.debug("forward_upstream", **summarize_env(envelope, prefix=""))

        processed_envelope: Optional[FameEnvelope] = None

        try:
            # Dispatch to all event listeners for security processing
            processed_envelope = await self._dispatch_envelope_event(
                "on_forward_upstream", self, envelope, context=context
            )

            # If any listener returns None, halt forwarding (envelope queued for keys)
            if processed_envelope is None:
                return

            if not self._upstream_connector:
                logger.debug(f"No upstream parent for '{self.physical_path}'")
                return

            assert self._session_manager
            assert isinstance(self._session_manager, UpstreamSessionManager)

            await self._session_manager.send(processed_envelope)
        except Exception as e:
            # Capture the exception for the completion event
            await self._dispatch_envelope_event(
                "on_forward_upstream_complete",
                self,
                processed_envelope or envelope,
                error=e,
                context=context,
            )
            # Re-raise the original exception
            raise
        else:
            # No exception occurred - call completion event without error
            await self._dispatch_envelope_event(
                "on_forward_upstream_complete", self, processed_envelope or envelope, context=context
            )

    async def send(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        delivery_policy: Optional[DeliveryPolicy] = None,
        delivery_fn: Optional[
            Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[Any]]
        ] = None,
        timeout_ms: Optional[int] = None,
    ) -> Optional[DeliveryAckFrame]:
        logger.debug("sending_envelope", **summarize_env(envelope, prefix=""))
        if context is None:
            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL,
                from_system_id=self.id,
                from_connector=None,
            )
        else:
            assert context.origin_type is None or context.origin_type == DeliveryOriginType.LOCAL, (
                "Can only send with LOCAL origin context"
            )
            # assert context.from_system_id is None or context.from_system_id == self.id, (
            #     "from_system_id must match this node's id in LOCAL context"
            # )
            assert context.from_connector is None, "from_connector must be None in LOCAL context"

            context.origin_type = DeliveryOriginType.LOCAL
            # context.from_system_id = self.id
            context.from_connector = None

        if not delivery_fn:
            delivery_fn = self.deliver

        delivery_policy = delivery_policy or self._delivery_policy

        is_ack_required = bool(delivery_policy and delivery_policy.is_ack_required(envelope))

        if is_ack_required:
            if envelope.rtype is None:
                envelope.rtype = FameResponseType.ACK
            else:
                envelope.rtype |= FameResponseType.ACK

        is_reply_required = envelope.rtype is not None and (
            envelope.rtype & FameResponseType.REPLY or envelope.rtype & FameResponseType.STREAM
        )

        if not envelope.trace_id:
            envelope.trace_id = generate_id()

        if not is_ack_required and not is_reply_required:
            return await delivery_fn(envelope, context)

        retry_policy = delivery_policy.sender_retry_policy if delivery_policy else None

        if not envelope.corr_id:
            envelope.corr_id = generate_id()

        if envelope.reply_to is None:
            from naylence.fame.node.node import SYSTEM_INBOX

            envelope.reply_to = format_address(SYSTEM_INBOX, self.physical_path)

        retry_handler = None
        if retry_policy:
            retry_handler = _DefaultRetryHandler(delivery_fn=delivery_fn)

        timeout_ms = timeout_ms or DEFAULT_INVOKE_TIMEOUT_MILLIS

        await self._delivery_tracker.track(
            envelope=envelope,
            expected_response_type=envelope.rtype or FameResponseType.ACK,
            timeout_ms=timeout_ms,
            retry_policy=retry_policy,
            retry_handler=retry_handler,
        )

        await delivery_fn(envelope, context)

        if is_ack_required:
            logger.debug("waiting_for_ack_post_send", **summarize_env(envelope, prefix=""))
            ack_env = await self._delivery_tracker.await_ack(
                envelope_id=envelope.id,
                timeout_ms=timeout_ms,
            )

            assert isinstance(ack_env.frame, DeliveryAckFrame), "Expected DeliveryAckFrame in response"

            return ack_env.frame

    async def deliver(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        # Dispatch to all event listeners for security processing
        processed_envelope = await self._dispatch_envelope_event(
            "on_deliver", self, envelope, context=context
        )

        # If any listener returns None, halt delivery (security violation or envelope queued for keys)
        if processed_envelope is None:
            return

        frame = processed_envelope.frame

        # Control frames bubble upstream as before
        if frame.type in [
            "AddressBind",
            "AddressUnbind",
            "CapabilityAdvertise",
            "CapabilityWithdraw",
            "NodeHeartbeat",
        ]:
            if self._upstream_connector:
                await self.forward_upstream(processed_envelope, context)
            return

        if frame.type in [
            "AddressBindAck",
            "AddressUnbindAck",
            "CapabilityAdvertiseAck",
            "CapabilityWithdrawAck",
        ]:
            await self._delivery_tracker.on_envelope_delivered(SYSTEM_INBOX, envelope, context)
            return

        # KeyAnnounce frames are now handled by the security manager in on_deliver
        # No need to handle them here anymore

        if frame.type in [
            "Data",
            "DeliveryAck",
            "SecureOpen",
            "SecureAccept",
            "SecureClose",
        ]:
            # Local delivery via explicit `to`
            if processed_envelope.to and self.has_local(processed_envelope.to):
                await self.deliver_local(processed_envelope.to, processed_envelope, context)
                return

            # Fallback: resolve by capabilities
            if processed_envelope.capabilities:
                resolved = await self._service_manager.resolve_address_by_capability(
                    processed_envelope.capabilities
                )
                if resolved:
                    await self.deliver_local(resolved, processed_envelope, context)
                    return

        # No local match — forward upstream unless already from parent
        if self._upstream_connector and context and context.origin_type == DeliveryOriginType.LOCAL:
            if not context or context.from_connector is not self._upstream_connector:
                await self.forward_upstream(processed_envelope, context)
            else:
                logger.error(f"Attempted to redirect envelope back to upstream: {processed_envelope}")

    def has_local(self, address: FameAddress):
        # First check if there's an explicit binding
        if self._binding_manager.has_binding(address):
            return True

        # Also check if the address's physical path matches this node's physical path
        # This handles cases where envelopes are routed to this node's physical path
        # even if there's no explicit binding yet (e.g., during initialization)
        try:
            from naylence.fame.core import parse_address

            _, path = parse_address(address)

            # Check if the path matches this node's physical path
            if path == self.physical_path:
                return True
        except (ValueError, RuntimeError):
            # parse_address might fail or physical_path might not be available yet
            # In these cases, fall back to binding-only check
            pass

        return False

    def _get_source_system_id(self, context: Optional[FameDeliveryContext]):
        source_system_id = None
        if context and context.from_system_id:
            source_system_id = context.from_system_id
        return source_system_id

    async def _handle_delivery_ack(
        self,
        envelope: FameEnvelope,
        context: Optional[Any] = None,
    ) -> None:
        """Handle incoming DeliveryAck frames (including NACKs from policy violations)."""
        assert isinstance(envelope.frame, DeliveryAckFrame)
        if envelope.frame.ok:
            logger.debug(
                "delivery_ack_received",
                envp_id=envelope.id,
                corr_id=envelope.corr_id,
                ok=envelope.frame.ok,
            )
        else:
            # This is a NACK - log the violation for monitoring and debugging
            logger.warning(
                "delivery_nack_received",
                envp_id=envelope.id,
                corr_id=envelope.corr_id,
                code=envelope.frame.code,
                reason=envelope.frame.reason,
                from_system_id=(
                    context.from_system_id if context and hasattr(context, "from_system_id") else "unknown"
                ),
            )

            # Applications can override this method to handle specific NACK types
            # For example, retry logic, circuit breakers, etc.
            await self._on_delivery_nack(envelope.frame, envelope, context)

    async def _on_delivery_nack(
        self,
        frame: DeliveryAckFrame,
        envelope: FameEnvelope,
        context: Optional[Any] = None,
    ) -> None:
        """
        Handle delivery NACK responses. Override this method in subclasses to implement
        custom NACK handling logic (e.g., retries, circuit breakers, alerts).
        """
        # Default implementation: just log the NACK
        logger.debug(
            "delivery_nack_processed",
            envp_id=envelope.id,
            violation_code=frame.code,
            reason=frame.reason,
        )

        # Future enhancements could include:
        # - Retry logic for transient failures
        # - Circuit breaker pattern for persistent violations
        # - Metrics collection for violation patterns
        # - Application-specific error handling

    def __str__(self) -> str:
        return f"Node {self.id or '<unassigned>'}, defaultBindingPath: {self.default_binding_path}"
