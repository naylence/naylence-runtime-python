"""
Handles streaming RPC responses and async generators.
"""

import asyncio
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from naylence.fame.core import (
    FameDeliveryContext,
    FameEnvelope,
    FameMessageResponse,
)
from naylence.fame.node.response_context_manager import ResponseContextManager
from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class StreamingResponseHandler:
    """Handles streaming response processing for RPC calls."""

    def __init__(
        self,
        deliver_wrapper: Callable[
            [], Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[None]]
        ],
        envelope_factory,
        response_context_manager: ResponseContextManager,
    ):
        self._deliver_wrapper = deliver_wrapper
        self._envelope_factory = envelope_factory
        self._response_context_manager = response_context_manager

    def is_streaming_result(self, result: Any) -> bool:
        """Check if result is a streaming response (async iterator/generator)."""
        return (
            hasattr(result, "__aiter__")
            or hasattr(result, "__anext__")
            or asyncio.iscoroutinefunction(getattr(result, "__anext__", None))
        )

    def is_streaming_fame_message_response(self, result: Any) -> bool:
        """Check if result is an async iterator of FameMessageResponse objects."""
        if not self.is_streaming_result(result):
            return False

        # Check if it's specifically an iterator of FameMessageResponse
        # This is a heuristic - we'll validate the actual types when we iterate
        return hasattr(result, "__aiter__")

    async def handle_streaming_fame_message_responses(
        self,
        responses: AsyncIterator[FameMessageResponse],
        request_envelope: FameEnvelope,
        request_context: Optional[FameDeliveryContext],
    ) -> None:
        """
        Handle streaming FameMessageResponse objects.

        Args:
            responses: Async iterator of FameMessageResponse objects
            request_envelope: Original request envelope
            request_context: Original request context
        """
        logger.debug(
            "handling_streaming_fame_message_responses",
            request_id=request_envelope.id,
        )

        try:

            async def _async_wrapper():
                try:
                    async for response in responses:
                        if not isinstance(response, FameMessageResponse):
                            logger.warning(
                                "invalid_streaming_response_type",
                                expected="FameMessageResponse",
                                actual=type(response).__name__,
                                request_id=request_envelope.id,
                            )
                            continue

                        # Handle the response envelope
                        response_envelope = response.envelope
                        response_context = response.context

                        # If no context provided, create one
                        if response_context is None:
                            response_context = self._response_context_manager.create_response_context(
                                request_envelope, request_context
                            )

                        # Ensure response envelope has proper metadata
                        self._response_context_manager.ensure_response_metadata(
                            response_envelope, request_envelope, response_context
                        )

                        await self._deliver_wrapper()(response_envelope, response_context)

                except Exception as e:
                    logger.error(
                        "streaming_fame_response_error",
                        request_id=request_envelope.id,
                        error=str(e),
                        exc_info=True,
                    )

            await _async_wrapper()

        except Exception as e:
            logger.error(
                "streaming_fame_response_handler_error",
                request_id=request_envelope.id,
                error=str(e),
                exc_info=True,
            )

    async def handle_streaming_response(
        self,
        result: AsyncIterator[Any],
        request_envelope: FameEnvelope,
        request_context: Optional[FameDeliveryContext],
        reply_to: str,
        request_id: str,
    ) -> None:
        """
        Handle streaming response for regular RPC calls.

        Args:
            result: The async iterator result from the RPC handler
            request_envelope: Original request envelope
            request_context: Original request context
            reply_to: Address to send responses to
            request_id: ID of the original request
        """
        logger.debug(
            "handling_streaming_response",
            request_id=request_id,
            reply_to=reply_to,
        )

        try:

            async def _async_wrapper():
                try:
                    async for item in result:
                        # Create JSON-RPC response for each streamed item
                        from naylence.fame.core import DataFrame, make_response

                        response = make_response(request_id, item)
                        response_frame = DataFrame(payload=response)

                        # Create response envelope using the envelope factory (like the original)
                        response_envelope = self._envelope_factory.create_envelope(
                            trace_id=request_envelope.trace_id,
                            frame=response_frame,
                            to=reply_to,
                            corr_id=request_id,
                        )

                        # Create response context
                        response_context = self._response_context_manager.create_response_context(
                            request_envelope, request_context
                        )

                        # Ensure response metadata
                        self._response_context_manager.ensure_response_metadata(
                            response_envelope, request_envelope, response_context
                        )

                        await self._deliver_wrapper()(response_envelope, response_context)

                except Exception as e:
                    # Create an error response for the client
                    from naylence.fame.core import DataFrame, make_response

                    logger.error(
                        "streaming_response_error",
                        request_id=request_id,
                        error=str(e),
                        exc_info=True,
                    )

                    # Send error response back to the client
                    error_response = make_response(request_id, error={"code": -32000, "message": str(e)})
                    error_frame = DataFrame(payload=error_response)

                    error_envelope = self._envelope_factory.create_envelope(
                        trace_id=request_envelope.trace_id,
                        frame=error_frame,
                        to=reply_to,
                        corr_id=request_id,
                    )

                    # Create error response context
                    error_response_context = self._response_context_manager.create_response_context(
                        request_envelope, request_context
                    )

                    # Ensure error response metadata
                    self._response_context_manager.ensure_response_metadata(
                        error_envelope, request_envelope, error_response_context
                    )

                    await self._deliver_wrapper()(error_envelope, error_response_context)
                    return  # Don't send the final null response after an error

            await _async_wrapper()

            # Send final null response to signal end of stream (like the original implementation)
            from naylence.fame.core import DataFrame, make_response

            final_response = make_response(request_id, None)
            final_frame = DataFrame(payload=final_response)

            final_envelope = self._envelope_factory.create_envelope(
                trace_id=request_envelope.trace_id,
                frame=final_frame,
                to=reply_to,
                corr_id=request_id,
            )

            # Create final response context
            final_response_context = self._response_context_manager.create_response_context(
                request_envelope, request_context
            )

            # Ensure final response metadata
            self._response_context_manager.ensure_response_metadata(
                final_envelope, request_envelope, final_response_context
            )

            await self._deliver_wrapper()(final_envelope, final_response_context)

        except Exception as e:
            logger.error(
                "streaming_response_handler_error",
                request_id=request_id,
                error=str(e),
                exc_info=True,
            )
