"""
Channel frame handler for processing secure channel frames.
"""

from typing import Awaitable, Callable, Optional

from naylence.fame.core import EnvelopeFactory, FameDeliveryContext, FameEnvelope
from naylence.fame.core.protocol.frames import (
    SecureAcceptFrame,
    SecureCloseFrame,
    SecureOpenFrame,
)
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.security.encryption.secure_channel_manager import (
    SecureChannelManager,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class SecureChannelFrameHandler:
    """Handler for secure channel frames (SecureOpen, SecureAccept, SecureClose)."""

    def __init__(
        self,
        secure_channel_manager: Optional[SecureChannelManager],
        envelope_factory: EnvelopeFactory,
        send_callback: Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[None]],
        envelope_security_handler: Optional[EnvelopeSecurityHandler] = None,
    ):
        self._secure_channel_manager = secure_channel_manager
        self._envelope_factory = envelope_factory
        self._send_callback = send_callback
        self._envelope_security_handler = envelope_security_handler

    async def handle_secure_open(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming SecureOpenFrame."""
        if not self._secure_channel_manager:
            raise RuntimeError("SecureChannelManager is not initialized")

        frame = envelope.frame
        if not isinstance(frame, SecureOpenFrame):
            raise ValueError(f"Expected SecureOpenFrame, got {type(frame)}")

        logger.debug("received_secure_open", cid=frame.cid, algorithm=frame.alg)

        # Generate response
        accept_frame = await self._secure_channel_manager.handle_open_frame(frame)

        # Send response back to sender
        response_envelope = self._envelope_factory.create_envelope(
            to=envelope.reply_to, frame=accept_frame, corr_id=envelope.corr_id
        )

        # Create response context and request stickiness for channel encryption
        # When we successfully establish a channel, the client will use it for channel encryption,
        # so sessions should be sticky
        response_context = None
        if accept_frame.ok:
            # Import here to avoid circular imports
            from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

            response_context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL,
                stickiness_required=True,
                sticky_sid=envelope.sid,  # Use original envelope SID for stickiness
            )
            logger.debug(
                "stickiness_requested_for_channel_encryption",
                cid=frame.cid,
                reason="secure_channel_established",
            )

        # Call send callback with backward compatibility
        # Check if the callback accepts a context parameter
        import inspect

        sig = inspect.signature(self._send_callback)
        params = list(sig.parameters.keys())
        # Filter out 'self' if it's a method
        if params and params[0] == "self":
            params = params[1:]

        if len(params) >= 2:
            # New signature: send_callback(envelope, context)
            await self._send_callback(response_envelope, response_context)
        else:
            # Old signature: send_callback(envelope) - for backward compatibility
            await self._send_callback(response_envelope, None)
        logger.debug("sent_secure_accept", cid=frame.cid, ok=accept_frame.ok)

        # Notify envelope security handler if channel was established
        if accept_frame.ok and self._envelope_security_handler:
            # Extract destination from channel ID if it follows our pattern
            if frame.cid.startswith("auto-") and "-" in frame.cid:
                parts = frame.cid.split("-")
                if len(parts) >= 3:
                    destination = "-".join(parts[1:-1])  # Everything between "auto" and the final ID
                    await self._envelope_security_handler.handle_channel_handshake_complete(
                        frame.cid, destination
                    )

    async def handle_secure_accept(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming SecureAcceptFrame."""
        if not self._secure_channel_manager:
            raise RuntimeError("SecureChannelManager is not initialized")

        frame = envelope.frame
        if not isinstance(frame, SecureAcceptFrame):
            raise ValueError(f"Expected SecureAcceptFrame, got {type(frame)}")

        logger.debug("received_secure_accept", cid=frame.cid, ok=frame.ok)

        # Complete handshake
        success = await self._secure_channel_manager.handle_accept_frame(frame)

        if not success:
            logger.warning("failed_to_complete_channel", cid=frame.cid)
        else:
            logger.debug("channel_established", cid=frame.cid)

            # Notify envelope security handler if channel was established
            if self._envelope_security_handler:
                # Extract destination from channel ID if it follows our pattern
                if frame.cid.startswith("auto-") and "-" in frame.cid:
                    parts = frame.cid.split("-")
                    if len(parts) >= 3:
                        destination = "-".join(parts[1:-1])  # Everything between "auto" and the final ID
                        await self._envelope_security_handler.handle_channel_handshake_complete(
                            frame.cid, destination
                        )

        # Handle negative SecureAcceptFrame (handshake failure)
        if not frame.ok and self._envelope_security_handler:
            # Extract destination from channel ID if it follows our pattern
            if frame.cid.startswith("auto-") and "-" in frame.cid:
                parts = frame.cid.split("-")
                if len(parts) >= 3:
                    destination = "-".join(parts[1:-1])  # Everything between "auto" and the final ID
                    await self._envelope_security_handler.handle_channel_handshake_failed(
                        frame.cid, destination, "negative_secure_accept"
                    )
                    logger.debug(
                        "notified_handshake_failure",
                        cid=frame.cid,
                        destination=destination,
                    )

    async def handle_secure_close(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming SecureCloseFrame."""
        if not self._secure_channel_manager:
            raise RuntimeError("SecureChannelManager is not initialized")

        frame = envelope.frame
        if not isinstance(frame, SecureCloseFrame):
            raise ValueError(f"Expected SecureCloseFrame, got {type(frame)}")

        logger.debug("received_secure_close", cid=frame.cid, reason=frame.reason)

        # Close the channel
        self._secure_channel_manager.handle_close_frame(frame)
