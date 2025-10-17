"""
RPC Client Manager - handles outbound RPC calls (invoke and invoke_stream).

This module is responsible for:
- Managing RPC reply listeners
- Sending RPC requests and awaiting responses
- Handling streaming RPC responses
- Managing pending RPC requests and timeouts
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from naylence.fame.core import (
    DEFAULT_INVOKE_TIMEOUT_MILLIS,
    DataFrame,
    DeliveryAckFrame,
    DeliveryOriginType,
    EnvelopeFactory,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    JSONRPCError,
    JSONRPCResponse,
    format_address,
    generate_id,
    make_request,
    parse_response,
)
from naylence.fame.delivery.delivery_tracker import (
    DeliveryTracker,
    DeliveryTrackerEventHandler,
    TrackedEnvelope,
)
from naylence.fame.util import logging
from naylence.fame.util.envelope_context import current_trace_id

logger = logging.getLogger(__name__)


class RPCClientManager(DeliveryTrackerEventHandler):
    """
    Manages outbound RPC calls and response handling.

    Handles:
    - RPC request/response lifecycle
    - Streaming RPC responses
    - Reply listener management
    - Timeout and error handling
    """

    def __init__(
        self,
        get_physical_path: Callable[[], str],
        get_id: Callable[[], str],
        get_sid: Callable[[], str],
        deliver_wrapper: Callable[
            [], Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[None]]
        ],
        envelope_factory: EnvelopeFactory,
        listen_callback: Callable[[str, Any], Awaitable[FameAddress]],
        delivery_tracker: DeliveryTracker,
    ) -> None:
        self._get_physical_path = get_physical_path
        self._get_id = get_id
        self._get_sid = get_sid
        self._deliver_wrapper = deliver_wrapper
        self._envelope_factory = envelope_factory
        self._delivery_tracker = delivery_tracker
        if self._delivery_tracker:
            self._delivery_tracker.add_event_handler(self)

        self._listen_callback = listen_callback

        # self._rpc_pending: Dict[int | str, asyncio.Future] = {}
        self._rpc_reply_address: FameAddress | None = None
        self._rpc_listener_address: FameAddress | None = None
        self._rpc_bound = False

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
        if not target_addr and not capabilities:
            raise ValueError("Either target address or capabilities must be provided")

        if target_addr and capabilities:
            raise ValueError("Both target address or capabilities must not be provided")

        logger.debug(
            "rpc_invoke_start",
            method=method,
            target_address=target_addr,
            capabilities=capabilities,
            timeout_ms=timeout_ms,
        )

        if not self._rpc_bound:
            await self._setup_rpc_reply_listener()

        request_id = generate_id()
        request = make_request(id=request_id, method=method, params={**params})

        frame = DataFrame(payload=request)

        envelope = self._envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=frame,
            to=target_addr,
            capabilities=capabilities,
            reply_to=self._rpc_reply_address,
            corr_id=request_id,
            response_type=FameResponseType.REPLY,
        )

        await self._send_rpc_request(request_id, envelope, FameResponseType.REPLY, timeout_ms)

        reply_envelope: FameEnvelope = await self._delivery_tracker.await_reply(envelope.id)
        if isinstance(reply_envelope.frame, DataFrame):
            logger.debug(
                "rpc_received_reply_with_tracker",
                request_id=request_id,
                reply_envp_id=reply_envelope.id,
            )
            result = parse_response(reply_envelope.frame.payload)
            if result.error:
                logger.error("rpc_error_response", request_id=request_id, error=str(result.error))
                raise Exception(result.error.message or "RPC error")
            return result.result

    async def invoke_stream(
        self,
        *,
        target_addr: Optional[FameAddress] = None,
        capabilities: Optional[list[str]] = None,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> AsyncIterator[JSONRPCResponse]:
        """
        Invoke a JSON-RPC request and stream back every JSONRPCResponse
        (e.g. for tasks/sendSubscribe).
        """

        if not target_addr and not capabilities:
            raise ValueError("Either target address or capabilities must be provided")

        if target_addr and capabilities:
            raise ValueError("Both target address or capabilities must not be provided")

        request_id = generate_id()

        # bind the listener; reply_addr is where we must set reply_to
        if not self._rpc_bound:
            await self._setup_rpc_reply_listener()

        # 2) Send the JSON-RPC request with reply_to pointing at our new listener
        request = make_request(id=request_id, method=method, params={**params})

        frame = DataFrame(payload=request)

        envelope = self._envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=frame,
            to=target_addr,
            capabilities=capabilities,
            reply_to=self._rpc_reply_address,
            corr_id=request_id,
            response_type=FameResponseType.STREAM,
        )

        await self._send_rpc_request(request_id, envelope, FameResponseType.STREAM, timeout_ms)

        logger.debug(
            "streaming_rpc_request_sent",
            request_id=request_id,
            target_address=target_addr,
        )

        async for reply_envelope in self._delivery_tracker.iter_stream(envelope.id, timeout_ms=timeout_ms):
            assert isinstance(reply_envelope, FameEnvelope)
            if isinstance(reply_envelope.frame, DataFrame):
                res = parse_response(reply_envelope.frame.payload)
                if res.error:
                    raise Exception(res.error.message or "RPC error")
                if res.result is None:
                    break
                yield res.result
            elif isinstance(reply_envelope.frame, DeliveryAckFrame):
                assert reply_envelope.frame.ok is False  # NACK ⇒ propagate as an exception
                error_message = self._create_delivery_error_message(
                    reply_envelope.frame.code, reply_envelope.frame.reason
                )
                yield JSONRPCResponse(
                    error=JSONRPCError(
                        code=-32099,  # Undeliverable message
                        message=error_message,
                    )
                )

    async def _setup_rpc_reply_listener(self) -> None:
        if self._rpc_bound:
            return

        """Set up the RPC reply listener for handling invoke() responses."""
        recipient = f"__rpc__{generate_id()}"
        self._rpc_reply_address = format_address(recipient, self._get_physical_path())
        logger.debug(
            "binding_rpc_reply_listener",
            reply_recipient=recipient,
            reply_address=self._rpc_reply_address,
        )

        self._rpc_listener_address = await self._listen_callback(recipient, None)
        self._rpc_bound = True
        logger.debug("rpc_reply_listener_bound", address=self._rpc_listener_address)

    def _create_delivery_error_message(
        self, code: Optional[str] = None, reason: Optional[str] = None
    ) -> str:
        """Create a user-friendly error message for delivery failures."""
        if code == "crypto_level_violation":
            return (
                "Message rejected due to insufficient encryption. "
                "The target service requires encrypted messages, but this message was sent in plaintext. "
                "Enable encryption in your security policy or use a channel encryption method."
            )
        elif code == "signature_required":
            return (
                "Message rejected because it lacks a required digital signature. "
                "The target service requires all messages to be signed. "
                "Configure an envelope signer in your node to automatically sign outbound messages."
            )
        elif code == "signature_verification_failed":
            return (
                "Message rejected because its digital signature could not be verified. "
                "This may indicate a security issue or mismatched signing keys. "
                "Check that the correct signing keys are configured and trusted."
            )
        else:
            # Generic fallback for unknown codes
            base_message = f"Message delivery failed with code '{code or 'unknown'}'"
            if reason:
                base_message += f": {reason}"
            return base_message

    async def cleanup(self) -> None:
        """Clean up pending RPC requests."""
        # Cancel any pending requests
        self._rpc_bound = False
        self._rpc_reply_address = None
        self._rpc_listener_address = None

    async def on_envelope_replied(self, envelope: TrackedEnvelope, reply_envelope: FameEnvelope) -> None:
        logger.debug(
            "rpc_envelope_replied",
            request_id=envelope.original_envelope.id,
            reply_id=reply_envelope.id,
        )

    async def _send_rpc_request(
        self,
        request_id: str,
        envelope: FameEnvelope,
        expected_response_type: FameResponseType,
        timeout_ms: int,
    ) -> None:
        """Send an RPC request envelope."""

        logger.debug(
            "sending_rpc_request",
            envp_id=envelope.id,
            corr_id=envelope.corr_id,
            request_id=request_id,
            target_address=envelope.to,
            expected_response_type=expected_response_type.name,
        )

        # await self._delivery_tracker.track(
        #     envelope,
        #     timeout_ms=timeout_ms,
        #     expected_response_type=expected_response_type,
        # )

        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id=self._get_id(),
            expected_response_type=expected_response_type,
        )

        await self._deliver_wrapper()(envelope, context)
