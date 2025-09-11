"""
Channel Polling Manager - handles the message polling loops for envelope listeners.

This module is responsible for:
- Managing the continuous polling for messages from channels
- Extracting envelopes and contexts from channel messages
- Delegating envelope processing to handlers
- Managing polling loop lifecycle and error handling
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional

from naylence.fame.core import (
    DEFAULT_POLLING_TIMEOUT_MS,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    extract_envelope_and_context,
)
from naylence.fame.errors.errors import FameTransportClose
from naylence.fame.util import logging
from naylence.fame.util.envelope_context import envelope_context

if TYPE_CHECKING:
    from naylence.fame.node.response_context_manager import ResponseContextManager

logger = logging.getLogger(__name__)


class ChannelPollingManager:
    """
    Manages message polling loops for channel listeners.

    Handles:
    - Continuous polling for messages from bound channels
    - Message extraction and envelope/context creation
    - Handler delegation and response processing
    - Error handling and timeout management
    """

    def __init__(
        self,
        deliver_wrapper: Callable[
            [], Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[None]]
        ],
        get_id: Callable[[], str],
        get_sid: Callable[[], str],
        response_context_manager: ResponseContextManager,
    ) -> None:
        self._deliver_wrapper = deliver_wrapper
        self._get_id = get_id
        self._get_sid = get_sid
        self._response_context_manager = response_context_manager

    async def start_polling_loop(
        self,
        service_name: str,
        channel: Any,
        handler: FameEnvelopeHandler,
        stop_state: Dict[str, bool],
        poll_timeout_ms: Optional[int] = DEFAULT_POLLING_TIMEOUT_MS,
    ) -> None:
        """
        Start the polling loop for a service listener.

        Args:
            service_name: Name of the service being listened to
            channel: The channel to poll for messages
            handler: The envelope handler to process incoming messages
            stop_state: Shared state dict to signal when to stop polling
            poll_timeout_ms: Timeout for each polling operation
        """
        logger.debug("poll_loop_started", recipient=service_name)
        try:
            while not stop_state["stopped"]:
                try:
                    message = await channel.receive(
                        timeout=int(poll_timeout_ms or DEFAULT_POLLING_TIMEOUT_MS / 1000)
                    )
                except asyncio.CancelledError:
                    logger.debug("listener_cancelled", recipient=service_name)
                    raise
                except FameTransportClose as close:
                    logger.debug("channel_closed", recipient=service_name, reason=close.reason)
                    break
                except TimeoutError:
                    continue
                except Exception as exc:
                    logger.error(
                        "transport_error",
                        recipient=service_name,
                        error=str(exc),
                        exc_info=True,
                    )
                    break

                if stop_state["stopped"] or message is None:
                    continue

                # Process the received message
                await self._process_channel_message(message, handler, service_name)

        finally:
            logger.debug("poll_loop_exiting", recipient=service_name)

    async def _process_channel_message(
        self,
        message: Any,
        handler: FameEnvelopeHandler,
        service_name: str,
    ) -> None:
        """
        Process a single message received from a channel.

        Args:
            message: The raw message received from the channel
            handler: The envelope handler to process the message
            service_name: Name of the service for logging
        """
        # Extract envelope and context from channel message

        env, delivery_context = extract_envelope_and_context(message)

        # Preserve the original inbound crypto level before handler processing
        # (it might get modified by security handlers during processing)
        # Note: We now handle this inside the individual response creation methods

        with envelope_context(env):
            try:
                result = await handler(env, delivery_context)

                # Process the handler result
                await self._process_handler_result(result, env, delivery_context, service_name)

            except Exception as e:
                logger.error("handler_crashed", recipient=service_name, error=e, exc_info=True)
                raise

    async def _process_handler_result(
        self,
        result: Any,
        env: FameEnvelope,
        delivery_context: Optional[FameDeliveryContext],
        service_name: str,
    ) -> None:
        """
        Process the result returned by an envelope handler.

        Args:
            result: The result returned by the handler
            env: The original request envelope
            delivery_context: The delivery context of the request
            service_name: Name of the service for logging
        """

        # Check if result is a FameMessageResponse
        from naylence.fame.core import FameMessageResponse

        if isinstance(result, FameMessageResponse):
            # Handler provided a response envelope - deliver it
            logger.debug(
                "delivering_envelope_response_message",
                service_name=service_name,
                response_envelope_id=result.envelope.id,
            )

            # Smart handling of response context and metadata
            response_envelope = result.envelope
            response_context = result.context

            # If no context provided, create one
            if response_context is None:
                logger.debug("creating_response_context", service_name=service_name)
                response_context = self._create_response_context(delivery_context)

            # Ensure response has proper metadata using response context manager
            self._response_context_manager.ensure_response_metadata(
                response_envelope, env, response_context
            )

            await self._deliver_wrapper()(response_envelope, response_context)

        elif self._is_streaming_fame_message_response(result):
            # Handler returned an async generator of FameMessageResponse objects - handle streaming
            logger.debug(
                "handling_streaming_fame_message_responses",
                service_name=service_name,
                envelope_id=env.id,
            )
            await self._handle_streaming_fame_message_responses(result, env, delivery_context)
        # Note: For envelope handlers, None result (no response) is the default

    def _create_response_context(
        self,
        delivery_context: Optional[FameDeliveryContext],
    ) -> FameDeliveryContext:
        """Create a response context with proper crypto level inheritance."""
        from naylence.fame.core import DeliveryOriginType

        # Extract crypto level directly from the delivery context
        orig_request_crypto_level = (
            delivery_context.security.inbound_crypto_level
            if delivery_context
            and delivery_context.security
            and delivery_context.security.inbound_crypto_level
            else None
        )

        # Create security context for response
        from naylence.fame.core.protocol.delivery_context import SecurityContext

        response_security = None
        if orig_request_crypto_level is not None or (
            delivery_context and delivery_context.security and delivery_context.security.crypto_channel_id
        ):
            # Copy signature information from the original request for signature mirroring
            original_was_signed = None
            if (
                delivery_context
                and delivery_context.security
                and hasattr(delivery_context.security, "inbound_was_signed")
            ):
                original_was_signed = delivery_context.security.inbound_was_signed

            response_security = SecurityContext(
                inbound_crypto_level=orig_request_crypto_level,
                inbound_was_signed=original_was_signed,
                crypto_channel_id=(
                    delivery_context.security.crypto_channel_id
                    if delivery_context and delivery_context.security
                    else None
                ),
            )

        # Create response context with security info and message-type metadata
        return FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id=self._get_id(),
            # For responses, security.inbound_crypto_level represents the original request's crypto level
            security=response_security,
            # Mark this as a response for proper policy decision making
            meta={"message-type": "response"},
        )

    def _is_streaming_fame_message_response(self, result: Any) -> bool:
        """Check if result is an async generator of FameMessageResponse objects."""
        import types

        # Check for async generators first
        if hasattr(result, "__aiter__") and hasattr(result, "__anext__"):
            return True

        # Check for regular generators
        if isinstance(result, types.GeneratorType):
            return True

        # Check for async iterators (but not basic iterables like str, list, dict)
        if hasattr(result, "__aiter__") and not isinstance(result, (str | bytes | dict | list | tuple)):
            return True

        return False

    async def _handle_streaming_fame_message_responses(
        self,
        result: Any,
        env: FameEnvelope,
        delivery_context: Optional[FameDeliveryContext],
    ):
        """Handle streaming of FameMessageResponse objects from envelope handlers."""
        import asyncio
        import types

        logger.debug(
            "entered_streaming_fame_message_handler",
            service_name=env.to,
            envelope_id=env.id,
            result_type=type(result).__name__,
        )

        # Convert regular generator to async iterator if needed
        if isinstance(result, types.GeneratorType):
            logger.debug("converting_generator_to_async", service_name=env.to, envelope_id=env.id)

            # Convert regular generator to async generator
            async def _async_wrapper():
                for item in result:
                    yield item

            async_iter = _async_wrapper()
        elif hasattr(result, "__aiter__"):
            logger.debug("using_existing_async_iterator", service_name=env.to, envelope_id=env.id)
            async_iter = result
        else:
            # Should not happen as we check for streaming above
            logger.error(
                "invalid_streaming_type",
                service_name=env.to,
                envelope_id=env.id,
                result_type=type(result).__name__,
            )
            raise ValueError("Result is not a valid streaming type")

        # Send each FameMessageResponse in the stream
        try:
            logger.debug(
                "starting_streaming_fame_message_iteration",
                service_name=env.to,
                envelope_id=env.id,
            )
            item_count = 0

            async for fame_message_response in async_iter:
                item_count += 1
                logger.debug(
                    "processing_streaming_fame_message",
                    service_name=env.to,
                    envelope_id=env.id,
                    item_count=item_count,
                )

                from naylence.fame.core import FameMessageResponse

                if not isinstance(fame_message_response, FameMessageResponse):
                    logger.error(
                        "invalid_streaming_item_type",
                        service_name=env.to,
                        envelope_id=env.id,
                        item_count=item_count,
                        expected_type="FameMessageResponse",
                        actual_type=type(fame_message_response).__name__,
                    )
                    continue

                # Handle the response envelope
                response_envelope = fame_message_response.envelope
                response_context = fame_message_response.context

                # If no context provided, create one
                if response_context is None:
                    logger.debug(
                        "creating_streaming_response_context",
                        service_name=env.to,
                        envelope_id=env.id,
                        item_count=item_count,
                    )
                    response_context = self._create_response_context(delivery_context)

                # Ensure response has proper metadata using response context manager
                self._response_context_manager.ensure_response_metadata(
                    response_envelope, env, response_context
                )

                logger.debug(
                    "delivering_streaming_fame_message",
                    service_name=env.to,
                    envelope_id=env.id,
                    item_count=item_count,
                    response_envelope_id=response_envelope.id,
                )
                # Send this response immediately with a timeout to detect hangs
                try:
                    await asyncio.wait_for(
                        self._deliver_wrapper()(response_envelope, response_context),
                        timeout=30.0,  # TODO: parameterize
                    )

                    logger.debug(
                        "delivered_streaming_fame_message",
                        service_name=env.to,
                        envelope_id=env.id,
                        item_count=item_count,
                        response_envelope_id=response_envelope.id,
                    )
                except asyncio.TimeoutError:
                    logger.error(
                        "streaming_fame_message_delivery_timeout",
                        service_name=env.to,
                        envelope_id=env.id,
                        item_count=item_count,
                        response_envelope_id=response_envelope.id,
                        exc_info=True,
                    )
                    # TODO: issue: re-raising the exception breaks further state of the system
                    # raise Exception(f"Delivery timeout for streaming FameMessageResponse {item_count}")
                except Exception as deliver_error:
                    logger.error(
                        "streaming_fame_message_delivery_error",
                        service_name=env.to,
                        envelope_id=env.id,
                        item_count=item_count,
                        response_envelope_id=response_envelope.id,
                        error=str(deliver_error),
                        error_type=type(deliver_error).__name__,
                    )
                    # TODO: issue: re-raising the exception breaks the further state of the system
                    # raise

                logger.debug(
                    "sent_streaming_fame_message",
                    service_name=env.to,
                    envelope_id=env.id,
                    item_count=item_count,
                )

                # Add a small delay to help with debugging and avoid overwhelming the system
                await asyncio.sleep(0.01)
                logger.debug(
                    "continuing_to_next_streaming_fame_message",
                    service_name=env.to,
                    envelope_id=env.id,
                    item_count=item_count,
                )

            logger.debug(
                "completed_streaming_fame_message_iteration",
                service_name=env.to,
                envelope_id=env.id,
                total_items=item_count,
            )

        except Exception as e:
            logger.exception(
                "streaming_fame_message_error",
                service_name=env.to,
                envelope_id=env.id,
                error=str(e),
            )
            raise
