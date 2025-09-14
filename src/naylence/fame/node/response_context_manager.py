"""
Response context management for preserving crypto levels in request-response flows.
"""

from typing import Callable, Optional

from naylence.fame.core import (
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class ResponseContextManager:
    """Manages response context creation and crypto level inheritance."""

    def __init__(self, get_id: Callable[[], str], get_sid: Callable[[], str]):
        self._get_id = get_id
        self._get_sid = get_sid

    def create_response_context(
        self,
        request_envelope: FameEnvelope,
        request_context: Optional[FameDeliveryContext],
    ) -> FameDeliveryContext:
        """
        Create a response context that properly inherits crypto levels from the request.

        Args:
            request_envelope: The original request envelope
            request_context: The request's delivery context (may be None)

        Returns:
            A properly configured response context
        """
        # Extract crypto level directly from the request context
        orig_request_crypto_level = None
        if request_context and request_context.security:
            orig_request_crypto_level = request_context.security.inbound_crypto_level

        orig_was_signed = (
            request_context.security.inbound_was_signed
            if request_context and request_context.security
            else False
        )

        # Create security context for response
        from naylence.fame.core.protocol.delivery_context import SecurityContext

        response_security = None
        if orig_request_crypto_level is not None or (
            request_context and request_context.security and request_context.security.crypto_channel_id
        ):
            response_security = SecurityContext(
                inbound_crypto_level=orig_request_crypto_level,
                inbound_was_signed=orig_was_signed,
                crypto_channel_id=(
                    request_context.security.crypto_channel_id
                    if request_context and request_context.security
                    else None
                ),
            )

        # Create response context with inherited crypto level
        response_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id=self._get_id(),
            # For responses, security.inbound_crypto_level represents the original request's crypto level
            # This allows the security policy to use inbound_crypto_level for mirroring decisions
            security=response_security,
        )

        logger.debug(
            "created_response_context",
            request_id=request_envelope.id,
            inherited_crypto_level=(orig_request_crypto_level.name if orig_request_crypto_level else None),
            channel_id=(response_context.security.crypto_channel_id if response_context.security else None),
        )

        return response_context

    def ensure_response_metadata(
        self,
        response_envelope: FameEnvelope,
        request_envelope: FameEnvelope,
        response_context: Optional[FameDeliveryContext] = None,
    ) -> None:
        """
        Ensure response envelope has proper metadata linking it to the request.

        Args:
            response_envelope: The response envelope to update
            request_envelope: The original request envelope
            response_context: Optional delivery context to set metadata on
        """
        # Always set metadata in context if provided (primary location)
        if response_context is not None:
            if response_context.meta is None:
                response_context.meta = {}

            response_context.meta["message-type"] = "response"

            # Link back to original request if we have it
            if request_envelope.id:
                response_context.meta["response-to-id"] = request_envelope.id

            # Force origin type to LOCAL for all responses sent by this node
            # This overrides any explicit origin type provided by the handler
            response_context.origin_type = DeliveryOriginType.LOCAL

            # Set the correct from_system_id for LOCAL origin
            response_context.from_system_id = self._get_id()

        # Also set metadata in envelope for backward compatibility
        # Always ensure envelope has proper metadata, regardless of whether context was provided
        # if response_envelope.meta is None:
        #     response_envelope.meta = {}

        # # Always set message-type to "response" in envelope meta for backward compatibility
        # response_envelope.meta["message-type"] = "response"

        # # Link back to original request if we have it
        # if request_envelope.id:
        #     response_envelope.meta["response-to-id"] = request_envelope.id

        # logger.debug(
        #     "ensured_response_metadata",
        #     response_id=response_envelope.id,
        #     request_id=request_envelope.id,
        # )
