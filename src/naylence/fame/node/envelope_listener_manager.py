"""
Refactored Listener Manager - now focused only on listener lifecycle management.

This is the main orchestrator that uses the extracted components:
- ChannelPollingManager: handles message polling loops
- RPCServerHandler: handles RPC request processing
- RPCClientManager: handles outbound RPC calls
- ResponseContextManager: handles response context creation
- StreamingResponseHandler: handles streaming responses
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional, Set

from naylence.fame.core import (
    DEFAULT_INVOKE_TIMEOUT_MILLIS,
    DEFAULT_POLLING_TIMEOUT_MS,
    Binding,
    EnvelopeFactory,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    FameRPCHandler,
)
from naylence.fame.delivery.delivery_tracker import DeliveryTracker, EnvelopeStatus, TrackedEnvelope
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.node.binding_manager import BindingManager
from naylence.fame.node.channel_polling_manager import ChannelPollingManager
from naylence.fame.node.node_like import NodeLike
from naylence.fame.node.response_context_manager import ResponseContextManager
from naylence.fame.node.rpc_client_manager import RPCClientManager
from naylence.fame.node.rpc_server_handler import RPCServerHandler
from naylence.fame.node.streaming_response_handler import StreamingResponseHandler
from naylence.fame.util import logging
from naylence.fame.util.task_spawner import TaskSpawner

logger = logging.getLogger(__name__)


class EnvelopeListener:
    def __init__(self, stop_fn: Callable[[], None], task: asyncio.Task) -> None:
        self._stop_fn = stop_fn
        self.task = task

    def stop(self) -> None:
        """Cancel the listener task and signal it to stop."""
        logger.debug("stopping_listener", task=self.task.get_name())
        self.task.cancel()
        self._stop_fn()


class EnvelopeListenerManager(TaskSpawner):
    """
    Manages long-running envelope listeners using modular components.

    This refactored version delegates specific responsibilities to focused components:
    - Channel polling and message processing
    - RPC server and client handling
    - Response context management
    - Streaming response processing
    """

    def __init__(
        self,
        *,
        binding_manager: BindingManager,
        node_like: NodeLike,
        envelope_factory: EnvelopeFactory,
        delivery_tracker: DeliveryTracker,
    ) -> None:
        super().__init__()
        logger.debug("initializing_envelope_listener_manager")
        self._binding_manager = binding_manager
        self._node_like = node_like

        _get_id = lambda: self._node_like.id  # # noqa: E731
        _get_sid: Callable[[], str] = lambda: self._node_like.sid  # type: ignore # noqa: E731

        async def deliver_fn(envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> Any:
            return await self._node_like.send(envelope, context)

        self._deliver = deliver_fn

        self._envelope_factory = envelope_factory
        self._delivery_tracker = delivery_tracker

        self._listeners: Dict[str, EnvelopeListener] = {}
        self._listeners_lock = asyncio.Lock()

        # Add handler mapping for recovery
        self._service_handlers: Dict[str, FameEnvelopeHandler] = {}
        self._service_handlers_lock = asyncio.Lock()

        # Track services that have failed inbound envelopes we should recover once a handler is registered
        self._pending_recovery_services: Set[str] = set()
        self._pending_recovery_envelopes: Dict[str, list[TrackedEnvelope]] = {}
        self._pending_recovery_services_lock = asyncio.Lock()

        # Per-service recovery locks to avoid duplicate concurrent recoveries
        self._service_recovery_locks: Dict[str, asyncio.Lock] = {}
        self._service_recovery_locks_lock = asyncio.Lock()

        # Initialize the modular components
        self._response_context_manager = ResponseContextManager(_get_id, _get_sid)

        self._streaming_response_handler = StreamingResponseHandler(
            lambda: deliver_fn, envelope_factory, self._response_context_manager
        )

        self._channel_polling_manager = ChannelPollingManager(
            lambda: deliver_fn, _get_id, _get_sid, self._response_context_manager
        )

        self._rpc_server_handler = RPCServerHandler(
            envelope_factory,
            _get_sid,
            self._response_context_manager,
            self._streaming_response_handler,
        )

        self._rpc_client_manager = RPCClientManager(
            get_physical_path=lambda: self._node_like.physical_path,
            get_id=_get_id,
            get_sid=_get_sid,
            deliver_wrapper=lambda: self._deliver,
            envelope_factory=envelope_factory,
            listen_callback=self._listen_for_client,
            delivery_tracker=self._delivery_tracker,
        )

    async def start(self) -> None:
        """Start the envelope listener manager and discover failed inbound envelopes."""
        await self.recover_unhandled_inbound_envelopes()

    async def recover_unhandled_inbound_envelopes(self) -> None:
        """
        Discover inbound envelopes that were in RECEIVED or FAILED_TO_HANDLE status.
        Defers actual recovery until a handler is registered via listen(service_name, handler).
        """
        if not self._delivery_tracker:
            return

        failed_inbound = await self._delivery_tracker.list_inbound(
            filter=lambda envelope: envelope.status
            in [EnvelopeStatus.RECEIVED, EnvelopeStatus.FAILED_TO_HANDLE]
        )
        if not failed_inbound:
            logger.debug("no_failed_inbound_envelopes_to_recover")
            return

        # Group envelopes by service and cache them
        grouped: Dict[str, list[TrackedEnvelope]] = {}
        for env in failed_inbound:
            svc = env.service_name or "unknown"
            grouped.setdefault(svc, []).append(env)

        async with self._pending_recovery_services_lock:
            self._pending_recovery_services.clear()
            self._pending_recovery_services.update(grouped.keys())
            self._pending_recovery_envelopes = grouped

        logger.debug(
            "discovered_failed_inbound_envelopes",
            total=len(failed_inbound),
            services=list(grouped.keys()),
        )

    async def _recover_service_if_needed(self, service_name: str) -> None:
        """
        If there are failed inbound envelopes for this service and a handler is registered,
        perform recovery now. Uses a per-service lock to prevent duplicate runs.
        """
        # Ensure we have a lock for this service
        async with self._service_recovery_locks_lock:
            lock = self._service_recovery_locks.get(service_name)
            if not lock:
                lock = asyncio.Lock()
                self._service_recovery_locks[service_name] = lock

        async with lock:
            # Verify a handler is registered
            async with self._service_handlers_lock:
                handler = self._service_handlers.get(service_name)
            if not handler:
                # Handler not registered; nothing to do
                return

            # Consume cached envelopes for this service
            async with self._pending_recovery_services_lock:
                envelopes = self._pending_recovery_envelopes.pop(service_name, [])
                # Clear the pending flag for the service either way
                self._pending_recovery_services.discard(service_name)

            if not envelopes:
                # Nothing cached; with no listener previously, there shouldn't be new failures
                logger.debug("no_cached_recovery_for_service", service_name=service_name)
                return

            logger.debug(
                "recovering_unhandled_envelopes_on_listen",
                service_name=service_name,
                count=len(envelopes),
                envelope_ids=[env.envelope_id for env in envelopes],
            )

            # Run the existing recovery path
            await self._recover_service_envelopes(service_name, envelopes)

    async def _recover_service_envelopes(self, service_name: str, envelopes: list[TrackedEnvelope]) -> None:
        """
        Recover envelopes for a specific service by resuming handler execution with retry logic.

        This method directly calls the handler with the failed envelope, resuming from where
        we left off without re-applying delivery transformations.
        """
        # Get the handler for this service
        async with self._service_handlers_lock:
            handler = self._service_handlers.get(service_name)

        if not handler:
            logger.error(
                "no_handler_found_for_recovery", service_name=service_name, envelope_count=len(envelopes)
            )
            return

        for tracked_envelope in envelopes:
            try:
                logger.warning(
                    "recovering_unhandled_envelope",
                    envelope_id=tracked_envelope.envelope_id,
                    service_name=service_name,
                    current_attempts=tracked_envelope.attempt,
                    status=tracked_envelope.status,
                )

                original_envelope = tracked_envelope.original_envelope

                # Create a basic delivery context (could be enhanced to restore from metadata)
                delivery_context = None

                # Get receiver retry policy from the node's delivery policy
                receiver_retry_policy = None
                if self._node_like.delivery_policy:
                    receiver_retry_policy = self._node_like.delivery_policy.receiver_retry_policy

                # Resume handler execution with retry logic - this will pick up from
                # the current attempt count and continue retrying
                await self._execute_handler_with_retries(
                    handler,
                    original_envelope,
                    delivery_context,
                    receiver_retry_policy,
                    tracked_envelope,
                    service_name,
                )

                logger.debug(
                    "envelope_recovery_completed",
                    envelope_id=tracked_envelope.envelope_id,
                    service_name=service_name,
                )

            except Exception as e:
                logger.error(
                    "envelope_recovery_failed",
                    envelope_id=tracked_envelope.envelope_id,
                    service_name=service_name,
                    error=str(e),
                )
                # The failure is already handled by _execute_handler_with_retries

    async def stop(self) -> None:
        """Stop all active listeners and clean up components."""
        async with self._listeners_lock:
            logger.debug("stopping_all_listeners", listeners=list(self._listeners.keys()))
            for listener in self._listeners.values():
                listener.stop()
            self._listeners.clear()

        # Clear handler mappings
        async with self._service_handlers_lock:
            self._service_handlers.clear()

        # Clean up RPC client state
        await self._rpc_client_manager.cleanup()

        await self.shutdown_tasks(grace_period=3.0)

    async def _execute_handler_with_retries(
        self,
        handler: FameEnvelopeHandler,
        env: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        retry_policy: Optional[RetryPolicy] = None,
        tracked_envelope: Optional[TrackedEnvelope] = None,  # TrackedEnvelope
        inbox_name: str = "",
    ) -> Any:
        """
        Execute a handler with retry logic based on receiver_retry_policy.

        This handles the scenario where ACK was sent successfully but handler execution fails.
        We retry the handler execution according to the retry policy, using the durable
        TrackedEnvelope.attempt counter that survives restarts.

        Args:
            handler: The envelope handler to execute
            env: The envelope to process
            context: Delivery context
            retry_policy: Retry configuration
            tracked_envelope: The tracked envelope for durable attempt counting
            inbox_name: Name of the inbox for failure reporting
        """
        if not retry_policy or retry_policy.max_retries == 0:
            # No retries configured, execute once
            try:
                result = await handler(env, context)
                # Mark as handled on success
                if tracked_envelope and self._delivery_tracker:
                    await self._delivery_tracker.on_envelope_handled(tracked_envelope, context=context)
                return result
            except Exception as e:
                # Even with no retries, we should report the failure
                if tracked_envelope and self._delivery_tracker:
                    tracked_envelope.attempt += 1
                    await self._delivery_tracker.on_envelope_handle_failed(
                        inbox_name, tracked_envelope, context=context, error=e, is_final_failure=True
                    )
                raise

        # Check if we should even attempt based on current attempt count
        current_attempt = tracked_envelope.attempt if tracked_envelope else 0
        max_attempts = retry_policy.max_retries + 1  # +1 for initial attempt

        if current_attempt >= max_attempts:
            # Already exhausted retries (e.g., after restart)
            logger.error(
                "handler_retries_already_exhausted",
                envelope_id=env.id,
                current_attempt=current_attempt,
                max_attempts=max_attempts,
            )
            error = RuntimeError(f"Handler retries exhausted: {current_attempt}/{max_attempts}")
            if tracked_envelope and self._delivery_tracker:
                await self._delivery_tracker.on_envelope_handle_failed(
                    inbox_name, tracked_envelope, context=context, error=error, is_final_failure=True
                )
            raise error

        last_exception = None

        # Execute attempts starting from current attempt count
        while current_attempt < max_attempts:
            try:
                # Increment attempt counter before trying
                if tracked_envelope:
                    tracked_envelope.attempt = current_attempt + 1

                result = await handler(env, context)

                # Mark as handled on success
                if tracked_envelope and self._delivery_tracker:
                    await self._delivery_tracker.on_envelope_handled(tracked_envelope, context=context)

                if current_attempt > 0:
                    logger.info(
                        "handler_retry_succeeded",
                        envelope_id=env.id,
                        attempt=current_attempt + 1,
                        total_attempts=current_attempt + 1,
                    )
                return result

            except Exception as e:
                last_exception = e
                attempt_number = current_attempt + 1

                # Call failure handler on every retry iteration
                if tracked_envelope and self._delivery_tracker:
                    is_final = attempt_number >= max_attempts
                    await self._delivery_tracker.on_envelope_handle_failed(
                        inbox_name, tracked_envelope, context=context, error=e, is_final_failure=is_final
                    )

                if attempt_number < max_attempts:
                    delay_ms = retry_policy.next_delay_ms(attempt_number)
                    logger.warning(
                        "handler_execution_failed_will_retry",
                        envelope_id=env.id,
                        attempt=attempt_number,
                        max_retries=retry_policy.max_retries,
                        delay_ms=delay_ms,
                        error=str(e),
                    )
                    await asyncio.sleep(delay_ms / 1000.0)
                    current_attempt += 1
                else:
                    logger.error(
                        "handler_execution_failed_exhausted_retries",
                        envelope_id=env.id,
                        total_attempts=attempt_number,
                        max_retries=retry_policy.max_retries,
                        error=str(e),
                    )
                    break

        # Re-raise the last exception after all retries are exhausted
        if last_exception:
            raise last_exception

    async def listen(
        self,
        service_name: str,
        handler: Optional[FameEnvelopeHandler] = None,
        *,
        capabilities: list[str] | None = None,
        poll_timeout_ms: Optional[int] = DEFAULT_POLLING_TIMEOUT_MS,
    ) -> FameAddress:
        """
        Start listening on a bound channel for envelopes addressed to `recipient`.
        Replaces any existing listener for the same recipient.
        """
        logger.debug("listen_start", recipient=service_name, poll_timeout_ms=poll_timeout_ms)

        # Store the handler for recovery purposes
        if handler:
            async with self._service_handlers_lock:
                self._service_handlers[service_name] = handler

            # Trigger deferred recovery for this service now that we have a handler
            self.spawn(
                self._recover_service_if_needed(service_name),
                name=f"recover-on-listen-{service_name}",
            )

        # Set up shared state for stopping the polling loop
        state: dict[str, bool] = {"stopped": False}

        # Bind to the channel
        binding: Binding = await self._binding_manager.bind(service_name, capabilities=capabilities)
        channel = binding.channel

        async def tracking_envelope_handler(
            env: FameEnvelope, context: Optional[FameDeliveryContext] = None
        ) -> Optional[Any]:
            tracked = None
            if self._delivery_tracker:
                tracked = await self._delivery_tracker.on_envelope_delivered(
                    service_name, env, context=context
                )
            if handler and (not tracked or tracked.status in [EnvelopeStatus.RECEIVED]):
                # Get receiver retry policy from the node's delivery policy
                receiver_retry_policy = None
                if self._node_like.delivery_policy:
                    receiver_retry_policy = self._node_like.delivery_policy.receiver_retry_policy

                # Check if this envelope has already had failed attempts (e.g., after restart)
                if tracked and tracked.attempt > 0:
                    logger.info(
                        "resuming_handler_retry_after_restart",
                        envelope_id=env.id,
                        current_attempts=tracked.attempt,
                        service_name=service_name,
                    )

                # Execute handler with retry logic
                result = await self._execute_handler_with_retries(
                    handler, env, context, receiver_retry_policy, tracked, service_name
                )

                return result

            return None

        # Create the polling loop task
        async def _poll_loop() -> None:
            await self._channel_polling_manager.start_polling_loop(
                service_name, channel, tracking_envelope_handler, state, poll_timeout_ms
            )

        # Start the polling task
        task = self.spawn(_poll_loop(), name=f"listener-{service_name}")
        listener = EnvelopeListener(stop_fn=lambda: state.update({"stopped": True}), task=task)

        # Replace any existing listener
        async with self._listeners_lock:
            if service_name in self._listeners:
                logger.debug("replacing_envelope_listener", recipient=service_name)
                old = self._listeners.pop(service_name)
                old.stop()
                try:
                    await old.task
                except asyncio.CancelledError:
                    pass
            self._listeners[service_name] = listener

        return binding.address

    async def listen_rpc(
        self,
        service_name: str,
        handler: FameRPCHandler,
        *,
        capabilities: list[str] | None = None,
        poll_timeout_ms: Optional[int] = DEFAULT_POLLING_TIMEOUT_MS,
    ) -> FameAddress:
        """
        Start an RPC listener for JSON-RPC requests on `service_name`.
        """
        logger.debug("rpc_listen_start", service_name=service_name)

        async def rpc_envelope_handler(
            env: FameEnvelope, handler_context: Optional[FameDeliveryContext] = None
        ) -> Optional[Any]:
            # Delegate to the RPC server handler
            return await self._rpc_server_handler.handle_rpc_request(
                env, handler_context, handler, service_name
            )

        # Use the envelope listener with our RPC envelope handler
        listener_address = await self.listen(
            service_name,
            rpc_envelope_handler,
            capabilities=capabilities,
            poll_timeout_ms=poll_timeout_ms,
        )

        logger.debug("rpc_listen_bound", service_name=service_name, address=listener_address)
        return listener_address

    async def invoke(
        self,
        *,
        target_addr: Optional[FameAddress] = None,
        capabilities: Optional[list[str]] = None,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> Any:
        """
        Invoke a JSON-RPC request to a remote service and await the response.
        """
        return await self._rpc_client_manager.invoke(
            target_addr=target_addr,
            capabilities=capabilities,
            method=method,
            params=params,
            timeout_ms=timeout_ms,
        )

    async def invoke_stream(
        self,
        *,
        target_addr: Optional[FameAddress] = None,
        capabilities: Optional[list[str]] = None,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ):
        """
        Invoke a JSON-RPC request and stream back every JSONRPCResponse.
        """
        async for result in self._rpc_client_manager.invoke_stream(
            target_addr=target_addr,
            capabilities=capabilities,
            method=method,
            params=params,
            timeout_ms=timeout_ms,
        ):
            yield result

    async def _listen_for_client(
        self, service_name: str, handler: Optional[FameEnvelopeHandler] = None
    ) -> FameAddress:
        """Helper method for RPC client to set up listeners."""
        return await self.listen(service_name, handler)
