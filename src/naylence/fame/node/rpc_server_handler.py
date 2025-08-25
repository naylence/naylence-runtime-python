"""
RPC Server Handler - handles inbound RPC requests and response creation.

This module is responsible for:
- Processing inbound JSON-RPC requests
- Calling user-defined RPC handlers
- Creating appropriate responses (traditional, streaming, or FameMessageResponse)
- Error handling and logging for RPC operations
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from naylence.fame.core import (
    DataFrame,
    EnvelopeFactory,
    FameDeliveryContext,
    FameEnvelope,
    FameRPCHandler,
    JSONRPCError,
    make_response,
    parse_request,
)
from naylence.fame.node.response_context_manager import ResponseContextManager
from naylence.fame.node.streaming_response_handler import StreamingResponseHandler
from naylence.fame.util import logging
from naylence.fame.util.util import pretty_model

logger = logging.getLogger(__name__)


class RPCServerHandler:
    """
    Handles inbound RPC requests and creates appropriate responses.

    Processes JSON-RPC requests and delegates to user handlers, then creates
    the appropriate response type (traditional JSON-RPC, streaming, or FameMessageResponse).
    """

    def __init__(
        self,
        envelope_factory: EnvelopeFactory,
        get_sid: Callable[[], str],
        response_context_manager: ResponseContextManager,
        streaming_response_handler: StreamingResponseHandler,
    ) -> None:
        self._envelope_factory = envelope_factory
        self._get_sid = get_sid
        self._response_context_manager = response_context_manager
        self._streaming_response_handler = streaming_response_handler

    async def handle_rpc_request(
        self,
        env: FameEnvelope,
        handler_context: Optional[FameDeliveryContext],
        handler: FameRPCHandler,
        service_name: str,
    ) -> Optional[Any]:
        """
        Handle an inbound RPC request envelope.

        Returns:
        - FameMessageResponse for direct envelope responses
        - None for streaming responses (handled internally)
        - None for requests without reply_to
        """

        assert isinstance(env.frame, DataFrame)

        logger.debug(
            "rpc_request_received",
            service_name=service_name,
            envelope_id=env.id,
            trace_id=env.trace_id,
            reply_to=env.reply_to,
        )

        try:
            payload = env.frame.payload
            request = parse_request(payload)
            logger.debug(
                "parsed_rpc_request",
                service_name=service_name,
                method=request.method,
                request_id=request.id,
                envelope_id=env.id,
                params_keys=list(request.params.keys()) if request.params else None,
            )
        except Exception as e:
            logger.warning("request_decode_error", error=str(e), envelope_id=env.id)
            return None

        logger.trace("handling_rpc_request", request=pretty_model(request))
        if not request.id:
            logger.warning("request_missing_id", request=request, envelope_id=env.id)
            return None

        # Extract reply_to early to use in both streaming and regular responses
        reply_to = env.reply_to or (request.params.get("reply_to") if request.params else None)
        if not reply_to:
            logger.warning(
                "missing_reply_to",
                service_name=service_name,
                request_id=request.id,
                envelope_id=env.id,
                env_reply_to=env.reply_to,
                params_reply_to=(request.params.get("reply_to") if request.params else None),
            )
            return None

        logger.debug(
            "extracted_reply_to",
            service_name=service_name,
            request_id=request.id,
            reply_to=reply_to,
            envelope_id=env.id,
        )

        try:
            logger.debug(
                "calling_rpc_handler",
                service_name=service_name,
                method=request.method,
                request_id=request.id,
                envelope_id=env.id,
            )
            result = await handler(request.method, request.params)
            logger.debug(
                "rpc_handler_returned",
                service_name=service_name,
                method=request.method,
                request_id=request.id,
                result_type=type(result).__name__,
                envelope_id=env.id,
                is_streaming=self._is_streaming_result(result),
            )

            # Check if result is a FameMessageResponse
            from naylence.fame.core import FameMessageResponse

            if isinstance(result, FameMessageResponse):
                # Handler provided a complete response envelope - return it for upstream delivery
                logger.debug(
                    "returning_response_message",
                    service_name=service_name,
                    request_id=request.id,
                    response_envelope_id=result.envelope.id,
                )
                return result
            elif self._is_streaming_result(result):
                # Result is an async iterator or generator - handle streaming
                logger.debug(
                    "handling_streaming_response",
                    service_name=service_name,
                    request_id=request.id,
                    envelope_id=env.id,
                    result_type=type(result).__name__,
                )
                # Cast to AsyncIterator since we've already verified it's streaming
                from typing import AsyncIterator, cast

                streaming_result = cast(AsyncIterator[Any], result)
                await self._streaming_response_handler.handle_streaming_response(
                    streaming_result,
                    env,
                    handler_context,
                    reply_to,
                    str(request.id),
                )
                return None  # Streaming handled internally
            else:
                # Traditional return value - create standard JSON-RPC response
                logger.debug(
                    "handling_traditional_response",
                    service_name=service_name,
                    request_id=request.id,
                    envelope_id=env.id,
                    result_type=type(result).__name__,
                )
                # Note: result can be None, which is a valid JSON-RPC response
                response = make_response(id=request.id, result=result)
        except Exception as e:
            logger.exception(
                "rpc_handler_error",
                service_name=service_name,
                error=str(e),
                request_id=request.id,
                envelope_id=env.id,
            )
            response = make_response(
                id=request.id,
                error=JSONRPCError(code=-32603, message=str(e), data=repr(e)),
            )

        # Traditional response path - create and deliver standard JSON-RPC response
        return await self._create_traditional_response(
            response, request, env, reply_to, handler_context, service_name
        )

    async def _create_traditional_response(
        self,
        response: Any,
        request: Any,
        env: FameEnvelope,
        reply_to: str,
        handler_context: Optional[FameDeliveryContext],
        service_name: str,
    ) -> Any:
        """Create a traditional JSON-RPC response envelope."""
        logger.debug(
            "creating_traditional_response_envelope",
            service_name=service_name,
            request_id=request.id,
            envelope_id=env.id,
            reply_to=reply_to,
        )
        frame = DataFrame(payload=response)

        out_env = self._envelope_factory.create_envelope(
            trace_id=env.trace_id,
            frame=frame,
            to=reply_to,
            corr_id=str(request.id) if request.id else None,
        )

        # Create response context using the context manager
        response_context = self._response_context_manager.create_response_context(env, handler_context)

        # Mark this as a response using context metadata
        if response_context.meta is None:
            response_context.meta = {}
        response_context.meta["message-type"] = "response"
        response_context.meta["response-to-id"] = env.id  # Link back to original request

        logger.debug(
            "sending_rpc_response",
            service_name=service_name,
            request_id=request.id,
            reply_to=reply_to,
            envelope_id=env.id,
            response_envelope_id=out_env.id,
        )

        # Return FameMessageResponse so the listener can deliver it
        from naylence.fame.core import FameMessageResponse

        logger.debug(
            "returning_traditional_response",
            service_name=service_name,
            request_id=request.id,
            envelope_id=env.id,
            response_envelope_id=out_env.id,
        )
        return FameMessageResponse(envelope=out_env, context=response_context)

    def _is_streaming_result(self, result: Any) -> bool:
        """Check if result should be treated as a streaming response."""
        import types

        # Check for async generators first
        if hasattr(result, "__aiter__") and hasattr(result, "__anext__"):
            return True

        # Check for regular generators
        if isinstance(result, types.GeneratorType):
            return True

        # Check for async iterators (but not basic iterables like str, list, dict)
        if hasattr(result, "__aiter__") and not isinstance(result, str | bytes | dict | list | tuple):
            return True

        return False
