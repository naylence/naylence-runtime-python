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
from typing import Any, Awaitable, Callable, Dict, Optional

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
from naylence.fame.delivery.delivery_tracker import DeliveryTracker
from naylence.fame.node.binding_manager import BindingManager
from naylence.fame.node.channel_polling_manager import ChannelPollingManager
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
        binding_manager: BindingManager,
        get_physical_path: Callable[[], str],
        get_sid: Callable[[], str],
        deliver: Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[None]],
        envelope_factory: EnvelopeFactory,
        delivery_tracker: DeliveryTracker,
    ) -> None:
        super().__init__()
        logger.debug("initializing_envelope_listener_manager")
        self._binding_manager = binding_manager
        self._deliver = deliver
        self._get_physical_path = get_physical_path
        self._get_sid = get_sid
        self._envelope_factory = envelope_factory
        self._delivery_tracker = delivery_tracker

        self._listeners: Dict[str, EnvelopeListener] = {}
        self._listeners_lock = asyncio.Lock()

        # Initialize the modular components
        self._response_context_manager = ResponseContextManager(get_sid)
        self._streaming_response_handler = StreamingResponseHandler(
            lambda: self._deliver, envelope_factory, self._response_context_manager
        )
        self._channel_polling_manager = ChannelPollingManager(
            lambda: self._deliver, get_sid, self._response_context_manager
        )
        self._rpc_server_handler = RPCServerHandler(
            envelope_factory,
            get_sid,
            self._response_context_manager,
            self._streaming_response_handler,
        )
        self._rpc_client_manager = RPCClientManager(
            get_physical_path,
            get_sid,
            deliver_wrapper=lambda: self._deliver,
            envelope_factory=envelope_factory,
            listen_callback=self._listen_for_client,
            delivery_tracker=self._delivery_tracker,
        )

    async def stop(self) -> None:
        """Stop all active listeners and clean up components."""
        async with self._listeners_lock:
            logger.debug("stopping_all_listeners", listeners=list(self._listeners.keys()))
            for listener in self._listeners.values():
                listener.stop()
            self._listeners.clear()

        # Clean up RPC client state
        await self._rpc_client_manager.cleanup()

        await self.shutdown_tasks(grace_period=3.0)

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

        # Set up shared state for stopping the polling loop
        state: dict[str, bool] = {"stopped": False}

        # Bind to the channel
        binding: Binding = await self._binding_manager.bind(service_name, capabilities=capabilities)
        channel = binding.channel

        async def tracking_envelope_handler(
            env: FameEnvelope, context: Optional[FameDeliveryContext] = None
        ) -> Optional[Any]:
            if self._delivery_tracker:
                await self._delivery_tracker.on_envelope_delivered(env, context=context)
            if handler:
                return await handler(env, context)

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
                logger.debug("replacing_listener", recipient=service_name)
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
