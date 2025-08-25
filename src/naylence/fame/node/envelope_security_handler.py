from __future__ import annotations

from typing import Optional

from naylence.fame.core import DeliveryOriginType, FameDeliveryContext, FameEnvelope
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionOptions,
    EncryptionStatus,
)
from naylence.fame.security.keys.key_management_handler import KeyManagementHandler
from naylence.fame.security.policy import SecurityPolicy
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class EnvelopeSecurityHandler:
    """Handler for envelope security operations (signing, verification, encryption, decryption)."""

    def __init__(
        self,
        *,
        node_like: NodeLike,
        envelope_signer: Optional[EnvelopeSigner] = None,
        envelope_verifier: Optional[EnvelopeVerifier] = None,
        encryption_manager: Optional[EncryptionManager] = None,
        security_policy: SecurityPolicy,
        key_management_handler: KeyManagementHandler,
    ):
        self._node_like = node_like
        self._envelope_signer = envelope_signer
        self._envelope_verifier = envelope_verifier
        self._encryption_manager = encryption_manager
        self._security_policy = security_policy
        self._key_management_handler = key_management_handler

    async def handle_outbound_security(self, envelope: FameEnvelope, context: FameDeliveryContext) -> bool:
        """
        Handle security for outbound envelopes (signing and encryption).
        Returns True if the envelope should continue delivery, False if queued for keys.
        """

        # Sign envelope if configured and not already signed
        should_sign = (
            await self._security_policy.should_sign_envelope(envelope, context, self._node_like)
            if self._security_policy
            else False
        )

        logger.debug(
            "checking_signing",
            has_signer=self._envelope_signer is not None,
            should_sign=should_sign,
            envp_id=envelope.id,
        )

        if should_sign:
            if not self._envelope_signer:
                raise RuntimeError("EnvelopeSigner is not configured")
            if not envelope.sid:
                envelope.sid = self._node_like.sid
            self._envelope_signer.sign_envelope(envelope, physical_path=self._node_like.physical_path)

        should_encrypt = (
            await self._security_policy.should_encrypt_envelope(envelope, context, self._node_like)
            if self._security_policy
            else False
        )

        # Encrypt envelope if configured and not already encrypted (DataFrames only)
        logger.debug(
            "checking_encryption",
            has_encryption_manager=self._encryption_manager is not None,
            should_encrypt=should_encrypt,
            envp_id=envelope.id,
            destination=str(envelope.to) if envelope.to else None,
        )

        # NEW: Use flexible crypto policy to decide outbound encryption level
        if self._encryption_manager and self._security_policy:
            # Skip encryption if envelope is already encrypted
            if envelope.sec and envelope.sec.enc:
                logger.debug(
                    "skipping_encryption_already_encrypted",
                    envp_id=envelope.id,
                    destination=str(envelope.to) if envelope.to else None,
                )
                return True

            # Check if this is a response envelope - use context meta for message-type
            message_type = None
            if context and context.meta:
                message_type = context.meta.get("message-type")

            is_response = message_type in ["response", "protocol-response"]

            if is_response:
                # This is a response - use response crypto policy

                # Get original request crypto level from delivery context's security inbound_crypto_level
                original_request_crypto_level = CryptoLevel.PLAINTEXT  # Default assumption
                if context and context.security and context.security.inbound_crypto_level:
                    original_request_crypto_level = context.security.inbound_crypto_level
                    logger.debug(
                        "using_context_crypto_level",
                        envp_id=envelope.id,
                        crypto_level=original_request_crypto_level.name,
                    )
                else:
                    logger.debug(
                        "no_crypto_level_info_using_default",
                        envp_id=envelope.id,
                        using_default=original_request_crypto_level.name,
                    )
                desired_crypto_level = await self._security_policy.decide_response_crypto_level(
                    original_request_crypto_level, envelope, context
                )
                # Get response-to-id from context meta
                response_to_id = None
                if context and context.meta:
                    response_to_id = context.meta.get("response-to-id")

                logger.debug(
                    "response_crypto_level_decided",
                    envp_id=envelope.id,
                    crypto_level=desired_crypto_level.name,
                    destination=str(envelope.to) if envelope.to else None,
                    original_request_id=response_to_id,
                    original_request_crypto_level=original_request_crypto_level.name,
                )
            else:
                # This is a regular outbound message - use outbound crypto policy
                desired_crypto_level = await self._security_policy.decide_outbound_crypto_level(
                    envelope, context, self._node_like
                )
                logger.debug(
                    "outbound_crypto_level_decided",
                    envp_id=envelope.id,
                    frame_type=envelope.frame.type,
                    crypto_level=desired_crypto_level.name,
                    destination=str(envelope.to) if envelope.to else None,
                )

            if desired_crypto_level == CryptoLevel.SEALED:
                # Force envelope-level encryption
                logger.debug("applying_sealed_encryption", envp_id=envelope.id)
                return await self._handle_sealed_encryption(envelope, context)
            elif desired_crypto_level == CryptoLevel.CHANNEL:
                # Force channel encryption
                logger.debug("applying_channel_encryption", envp_id=envelope.id)
                return await self._handle_channel_encryption(envelope, context)
            # If PLAINTEXT, continue without encryption

        # Fallback to legacy logic for backward compatibility
        elif self._encryption_manager and self._security_policy.should_encrypt_envelope(
            envelope, context, self._node_like
        ):
            return await self._handle_to_be_encrypted_envelope(envelope, context)

        return True

    async def handle_signed_envelope(self, envelope: FameEnvelope, context: FameDeliveryContext) -> bool:
        """
        Handle incoming signed envelopes - verify signature or queue for key.
        Returns True if the envelope is verified and should continue down
        the normal delivery path. Returns False if it was queued awaiting a key.
        """
        assert context, "Context must be provided for signature verification"
        assert context.origin_type, "Context origin type must be provided"
        assert envelope.sec and envelope.sec.sig
        assert self._envelope_verifier

        # Handle case where from_system_id is not yet available (e.g., during node attachment)
        from_system_id = context.from_system_id or "pending-attachment"
        if not context.from_system_id:
            logger.debug(
                "signed_envelope_during_attachment",
                envp_id=envelope.id,
                reason="from_system_id_not_yet_available",
            )

        kid = envelope.sec.sig.kid
        assert kid
        if await self._key_management_handler.has_key(kid):
            # Routers perform a shallow verification only (headers + fd).
            # The final recipient is responsible for checking the payload digest.
            verified = await self._envelope_verifier.verify_envelope(envelope, check_payload=False)
            if verified:
                logger.debug("envelope_verified", envp_id=envelope.id, sid=envelope.sid, kid=kid)
                return True  # ✔ verified – carry on
            else:
                # If verify_envelope returns False, it means verification failed
                # This should raise an exception to indicate failed verification
                raise ValueError(f"Envelope signature verification failed for kid={kid}")

        # Key missing ⇒ queue + request (once) and bail out
        self._key_management_handler._pending_envelopes.setdefault(kid, []).append((envelope, context))
        await self._key_management_handler._maybe_request_signing_key(
            kid, context.origin_type, from_system_id
        )
        logger.debug("queued_envelope_missing_signing_key", kid=kid, envp_id=envelope.id)
        return False

    async def _handle_to_be_encrypted_envelope_with_options(
        self,
        envelope: FameEnvelope,
        context: FameDeliveryContext,
        encryption_opts: EncryptionOptions,
    ) -> bool:
        """
        Handle envelope that needs encryption with specific encryption options.

        This method bypasses the security policy's get_encryption_options and uses
        the provided options directly.

        Returns True if the envelope was encrypted (or skipped) and should continue down
        the normal delivery path. Returns False if it was queued awaiting prerequisites.
        """
        from naylence.fame.core.protocol.frames import DataFrame

        assert context and context.origin_type
        assert self._encryption_manager

        # SECURITY CHECK: Only process LOCAL origin envelopes for encryption
        if context.origin_type != DeliveryOriginType.LOCAL:
            logger.warning("envelope_encryption_rejected_non_local", origin=context.origin_type)
            return True

        # Only encrypt DataFrames
        if not isinstance(envelope.frame, DataFrame):
            logger.trace(
                "skipping_encryption_non_dataframe",
                envp_id=envelope.id,
                frame_type=type(envelope.frame).__name__,
            )
            return True

        # Use the provided encryption options directly
        if not encryption_opts:
            logger.warning("no_encryption_options_provided", envp_id=envelope.id)
            return True

        logger.debug(
            "using_forced_encryption_options",
            envp_id=envelope.id,
            options=encryption_opts,
        )

        # Use the unified async encryption interface
        try:
            result = await self._encryption_manager.encrypt_envelope(envelope, opts=encryption_opts)

            if result.status == EncryptionStatus.QUEUED:
                logger.debug("envelope_queued_for_encryption", envp_id=envelope.id)

                # Handle queueing and key request through KeyManagementHandler
                await self._handle_encryption_queueing(envelope, context, encryption_opts)

                return False  # Don't continue delivery - envelope was queued

            elif result.status == EncryptionStatus.OK:
                logger.debug("envelope_encrypted", envp_id=envelope.id)
                # Update the envelope with the encrypted version
                if result.envelope:
                    envelope.frame = result.envelope.frame
                    envelope.sec = result.envelope.sec
                return True  # Continue delivery with encrypted envelope

            elif result.status == EncryptionStatus.SKIPPED:
                logger.debug("envelope_encryption_skipped", envp_id=envelope.id)
                return True  # Continue delivery with original envelope

            else:
                logger.warning(
                    "unknown_encryption_status",
                    envp_id=envelope.id,
                    status=result.status,
                )
                return True  # Continue delivery as fallback

        except Exception as e:
            logger.error("encryption_failed", envp_id=envelope.id, error=str(e))
            return True  # Continue delivery without encryption as fallback

    async def _handle_to_be_encrypted_envelope(
        self, envelope: FameEnvelope, context: FameDeliveryContext
    ) -> bool:
        """
        Handle envelope that needs encryption using the unified async encryption interface.

        This method now works with any encryption manager implementation through the
        standardized EncryptionResult interface, eliminating the need for specific
        branching on encryption types.

        Returns True if the envelope was encrypted (or skipped) and should continue down
        the normal delivery path. Returns False if it was queued awaiting prerequisites.
        """
        from naylence.fame.core.protocol.frames import DataFrame

        assert context and context.origin_type
        assert self._encryption_manager
        assert self._security_policy

        # SECURITY CHECK: Only process LOCAL origin envelopes for encryption
        if context.origin_type != DeliveryOriginType.LOCAL:
            logger.warning("envelope_encryption_rejected_non_local", origin=context.origin_type)
            return True

        # Only encrypt DataFrames
        if not isinstance(envelope.frame, DataFrame):
            logger.trace(
                "skipping_encryption_non_dataframe",
                envp_id=envelope.id,
                frame_type=type(envelope.frame).__name__,
            )
            return True

        # Get encryption options from security policy
        encryption_opts = await self._security_policy.get_encryption_options(
            envelope, context, self._node_like
        )
        if not encryption_opts:
            logger.warning("no_encryption_options_provided", envp_id=envelope.id)
            return True  # No encryption options, continue without encryption

        # Use the unified async encryption interface
        try:
            result = await self._encryption_manager.encrypt_envelope(envelope, opts=encryption_opts)

            if result.status == EncryptionStatus.QUEUED:
                logger.debug("envelope_queued_for_encryption", envp_id=envelope.id)

                # Handle queueing and key request through KeyManagementHandler
                await self._handle_encryption_queueing(envelope, context, encryption_opts)

                return False  # Don't continue delivery - envelope was queued

            elif result.status == EncryptionStatus.OK:
                logger.debug("envelope_encrypted", envp_id=envelope.id)
                # Update the envelope with the encrypted version
                if result.envelope:
                    envelope.frame = result.envelope.frame
                    envelope.sec = result.envelope.sec
                return True  # Continue delivery with encrypted envelope

            elif result.status == EncryptionStatus.SKIPPED:
                logger.debug("envelope_encryption_skipped", envp_id=envelope.id)
                return True  # Continue delivery with original envelope

            else:
                logger.warning(
                    "unknown_encryption_status",
                    envp_id=envelope.id,
                    status=result.status,
                )
                return True  # Continue delivery as fallback

        except Exception as e:
            logger.error("encryption_failed", envp_id=envelope.id, error=str(e))
            return True  # Continue delivery without encryption as fallback

    async def _handle_encryption_queueing(
        self,
        envelope: FameEnvelope,
        context: FameDeliveryContext,
        encryption_opts: EncryptionOptions,
    ) -> None:
        """
        Handle envelope queueing and key request when encryption prerequisites are missing.

        This method handles different types of encryption queueing:
        - Sealed encryption: queues envelope and initiates key requests through KeyManagementHandler
        - Channel encryption: acknowledges that queueing is handled internally by ChannelEncryptionManager
        """
        assert context.origin_type
        # Determine what type of key request is needed based on encryption options
        if "recip_kid" in encryption_opts:
            # Direct key ID request
            recip_kid = encryption_opts["recip_kid"]
            if self._key_management_handler:
                # Queue envelope in KeyManagementHandler
                if recip_kid not in self._key_management_handler._pending_encryption_envelopes:
                    self._key_management_handler._pending_encryption_envelopes[recip_kid] = []
                self._key_management_handler._pending_encryption_envelopes[recip_kid].append(
                    (envelope, context)
                )

                # Request the key by ID
                await self._key_management_handler._maybe_request_encryption_key(
                    recip_kid, context.origin_type, context.from_system_id or "unknown"
                )

        elif "request_address" in encryption_opts:
            # Address-based key request
            request_address = encryption_opts["request_address"]
            if self._key_management_handler:
                # Queue envelope using address as key
                address_key = str(request_address)
                if address_key not in self._key_management_handler._pending_encryption_envelopes:
                    self._key_management_handler._pending_encryption_envelopes[address_key] = []
                self._key_management_handler._pending_encryption_envelopes[address_key].append(
                    (envelope, context)
                )

                # Request the key by address
                await self._key_management_handler._maybe_request_encryption_key_by_address(
                    request_address,
                    context.origin_type,
                    context.from_system_id or "unknown",
                )

        elif encryption_opts.get("encryption_type") == "channel":
            # Channel encryption - queueing is handled internally by ChannelEncryptionManager
            # No action needed here as the envelope was already queued by the encryption manager
            logger.debug(
                "channel_encryption_queueing_handled_internally",
                envp_id=envelope.id,
                destination=encryption_opts.get("destination"),
            )

        else:
            # Unknown encryption options - log warning
            logger.warning(
                "unknown_encryption_queueing_options",
                envp_id=envelope.id,
                options=encryption_opts,
            )

    async def should_decrypt_envelope(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ) -> bool:
        """Check if envelope should be decrypted."""
        # Check for standard encryption using security policy
        if self._encryption_manager is not None and await self._security_policy.should_decrypt_envelope(
            envelope, context, self._node_like
        ):
            return True

        # Check for channel encryption using the policy's classification
        if envelope.sec and envelope.sec.enc:
            # Use the security policy to classify the message and check if it's channel encryption
            from naylence.fame.security.policy.security_policy import CryptoLevel

            crypto_level = self._security_policy.classify_message_crypto_level(envelope, context)
            if crypto_level == CryptoLevel.CHANNEL:
                return True

        return False

    async def decrypt_envelope(
        self, envelope: FameEnvelope, opts: Optional[EncryptionOptions] = None
    ) -> FameEnvelope:
        """Decrypt an envelope."""
        # Use the unified encryption manager interface
        if not self._encryption_manager:
            raise RuntimeError("No encryption manager available for decryption")
        return await self._encryption_manager.decrypt_envelope(envelope, opts=opts)

    def is_signed(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]) -> bool:
        """Check if envelope is signed."""
        return envelope.sec is not None and envelope.sec.sig is not None and context is not None

    async def handle_envelope_security(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ) -> tuple[FameEnvelope, bool]:
        """
        Handle inbound security processing for an envelope during delivery.

        This handles:
        - Inbound signature verification for incoming envelopes
        - Crypto level classification and storage in delivery context

        Note:
        - Outbound security (signing/encryption) is now handled in forward* methods
        - Decryption is handled in deliver_local() for envelopes being delivered to local bindings

        Returns:
            tuple[FameEnvelope, bool]: (processed_envelope, should_continue_delivery)
            - processed_envelope: The envelope after security processing
            - should_continue_delivery: True if delivery should continue, False if queued for keys
        """
        processed_envelope = envelope

        if context and context.origin_type == DeliveryOriginType.LOCAL:
            return (
                processed_envelope,
                True,
            )  # No inbound security processing needed for local origin

        # Classify and store inbound crypto level in delivery context
        if context and self._security_policy:
            inbound_crypto_level = self._security_policy.classify_message_crypto_level(envelope, context)

            # If the context already has a security.inbound_crypto_level set (e.g., from transport-level
            # security), preserve it if it's more secure than what the envelope content suggests
            if (
                context
                and context.security
                and hasattr(context.security, "inbound_crypto_level")
                and context.security.inbound_crypto_level is not None
            ):
                existing_level = context.security.inbound_crypto_level
                # Preserve existing level if it's more secure than the envelope-based classification
                from naylence.fame.security.policy.security_policy import CryptoLevel

                if (
                    existing_level == CryptoLevel.SEALED and inbound_crypto_level != CryptoLevel.SEALED
                ) or (
                    existing_level == CryptoLevel.CHANNEL and inbound_crypto_level == CryptoLevel.PLAINTEXT
                ):
                    logger.debug(
                        "preserving_existing_crypto_level",
                        envp_id=envelope.id,
                        existing_level=existing_level.name,
                        envelope_level=inbound_crypto_level.name,
                        reason="existing_level_more_secure",
                    )
                    # Keep the existing, more secure level
                    inbound_crypto_level = existing_level

            # Ensure context has security object
            if not context.security:
                from naylence.fame.core.protocol.delivery_context import SecurityContext

                context.security = SecurityContext()

            context.security.inbound_crypto_level = inbound_crypto_level

        # Track whether the inbound envelope was signed for signature mirroring
        if context and context.security is None:
            from naylence.fame.core.protocol.delivery_context import SecurityContext

            context.security = SecurityContext()

        if context and context.security:
            # Store whether this envelope is signed
            context.security.inbound_was_signed = self.is_signed(processed_envelope, context)

        # Handle inbound signature verification for signed envelopes
        if self.is_signed(processed_envelope, context) and context:
            if not await self.handle_signed_envelope(processed_envelope, context):
                return (
                    processed_envelope,
                    False,
                )  # queued – do not continue with normal delivery logic
        else:
            # Check if unsigned envelope should have been signed
            if context and self._security_policy.is_signature_required(processed_envelope, context):
                # Unsigned envelope that should be signed - handle violation

                # Critical frames must always be rejected if unsigned, regardless of policy
                from naylence.fame.core.protocol.frames import (
                    KeyAnnounceFrame,
                    KeyRequestFrame,
                    SecureAcceptFrame,
                    SecureOpenFrame,
                )

                is_critical_frame = isinstance(
                    processed_envelope.frame,
                    KeyRequestFrame | KeyAnnounceFrame | SecureOpenFrame | SecureAcceptFrame,
                )

                if is_critical_frame:
                    logger.error(
                        "critical_frame_unsigned_rejected",
                        envp_id=processed_envelope.id,
                        frame_type=processed_envelope.frame.type,
                        reason="critical_frames_must_be_signed",
                    )
                    return (
                        processed_envelope,
                        False,
                    )  # Always reject unsigned critical frames

                # For non-critical frames, use the policy violation action
                violation_action = self._security_policy.get_unsigned_violation_action(
                    processed_envelope, context
                )
                logger.warning(
                    "unsigned_envelope_violation",
                    envp_id=processed_envelope.id,
                    frame_type=processed_envelope.frame.type,
                    action=violation_action.name,
                )

                # Handle violation action
                from naylence.fame.security.policy.security_policy import SecurityAction

                if violation_action == SecurityAction.REJECT:
                    return processed_envelope, False  # Halt delivery
                elif violation_action == SecurityAction.NACK:
                    return processed_envelope, False  # Drop envelope
                # For SecurityAction.ALLOW, continue processing

        return processed_envelope, True

    async def handle_channel_handshake_complete(self, channel_id: str, destination: str):
        """
        Handle completion of a channel handshake.

        This method is called by the channel frame handler when a SecureAccept
        is received and the channel handshake is complete.
        """
        logger.debug(
            "channel_handshake_completed",
            channel_id=channel_id,
            destination=destination,
        )

        # Notify the channel encryption manager if it exists
        if self._encryption_manager and hasattr(self._encryption_manager, "notify_channel_established"):
            await self._encryption_manager.notify_channel_established(channel_id)
            logger.debug("notified_encryption_manager_channel_ready", channel_id=channel_id)

    async def handle_channel_handshake_failed(
        self, channel_id: str, destination: str, reason: str = "handshake_failed"
    ):
        """
        Handle failure of a channel handshake.

        This method is called by the channel frame handler when a negative SecureAcceptFrame
        is received, indicating that the channel handshake has failed. It notifies the
        encryption manager and ensures that any queued envelopes are properly handled.

        Args:
            channel_id: The ID of the channel that failed to establish
            destination: The destination address for the failed channel
            reason: A description of why the handshake failed
        """
        logger.debug(
            "channel_handshake_failed",
            channel_id=channel_id,
            destination=destination,
            reason=reason,
        )

        # Notify the channel encryption manager about the failure
        if self._encryption_manager:
            # Check if this is a ChannelEncryptionManager with failure notification capability
            if hasattr(self._encryption_manager, "notify_channel_failed"):
                # Use getattr to avoid type checker issues
                notify_method = getattr(self._encryption_manager, "notify_channel_failed")
                await notify_method(channel_id, reason)
                logger.debug(
                    "notified_encryption_manager_channel_failed",
                    channel_id=channel_id,
                    reason=reason,
                )
            else:
                logger.debug(
                    "encryption_manager_lacks_failure_notification",
                    manager_type=type(self._encryption_manager).__name__,
                    channel_id=channel_id,
                )

        # If the encryption manager doesn't have a specific failure notification method,
        # try to clear any queued envelopes for this destination through key management
        elif self._key_management_handler:
            # For channel encryption failures, we need to handle queued envelopes
            # that were waiting for this channel to be established
            await self._handle_failed_channel_envelope_cleanup(destination, reason)

    async def _handle_failed_channel_envelope_cleanup(self, destination: str, reason: str):
        """
        Clean up envelopes that were queued for a failed channel.

        Since channel encryption queuing is managed differently than key-based queuing,
        we need to check with the encryption manager to see if there are any envelopes
        that need to be notified of the failure.
        """
        logger.debug(
            "cleaning_up_failed_channel_envelopes",
            destination=destination,
            reason=reason,
        )

        # This is a placeholder for future enhancement. In practice, the ChannelEncryptionManager
        # should handle this internally when notify_channel_failed is called.
        # For now, we just log that cleanup was attempted.
        logger.debug(
            "channel_handshake_failure_cleanup_attempted",
            destination=destination,
            reason=reason,
            note="envelope_cleanup_handled_by_encryption_manager",
        )

    async def _handle_sealed_encryption(self, envelope: FameEnvelope, context: FameDeliveryContext) -> bool:
        """
        Handle sealed (envelope-level) encryption by looking up recipient keys.
        """
        if not envelope.to:
            logger.warning("sealed_encryption_requested_but_no_destination", envp_id=envelope.id)
            return True  # Continue without encryption as fallback

        # For sealed encryption, we need to get encryption options directly
        # but ensure we don't get channel encryption options
        logger.debug(
            "attempting_sealed_encryption",
            envp_id=envelope.id,
            destination=str(envelope.to),
        )

        try:
            # Get encryption options from the security policy
            # The policy should return sealed options since we're explicitly requesting sealed encryption
            encryption_opts = await self._security_policy.get_encryption_options(
                envelope, context, self._node_like
            )

            if encryption_opts:
                if encryption_opts.get("encryption_type") == "channel":
                    # The policy returned channel options even though we want sealed
                    # This shouldn't happen in normal operation, but handle it gracefully
                    logger.warning(
                        "policy_returned_channel_for_sealed_request",
                        envp_id=envelope.id,
                    )
                    # Force key request by address for sealed encryption
                    key_request_opts: EncryptionOptions = {"request_address": envelope.to}
                    return await self._handle_to_be_encrypted_envelope_with_options(
                        envelope, context, key_request_opts
                    )
                else:
                    # Use the sealed encryption options (should have recip_kid or request_address)
                    logger.debug(
                        "using_sealed_encryption_options",
                        envp_id=envelope.id,
                        options=encryption_opts,
                    )
                    return await self._handle_to_be_encrypted_envelope_with_options(
                        envelope, context, encryption_opts
                    )
            else:
                # No encryption options - request key by address
                logger.debug("no_encryption_options_requesting_key", envp_id=envelope.id)
                key_request_opts: EncryptionOptions = {"request_address": envelope.to}
                return await self._handle_to_be_encrypted_envelope_with_options(
                    envelope, context, key_request_opts
                )

        except Exception as e:
            # Key lookup failed - request it by address
            logger.debug("sealed_key_lookup_failed_requesting", envp_id=envelope.id, error=str(e))
            key_request_opts: EncryptionOptions = {"request_address": envelope.to}
            return await self._handle_to_be_encrypted_envelope_with_options(
                envelope, context, key_request_opts
            )

    async def _handle_channel_encryption(
        self, envelope: FameEnvelope, context: FameDeliveryContext
    ) -> bool:
        """
        Handle channel encryption by forcing channel encryption options.
        """
        if not envelope.to:
            logger.warning("channel_encryption_requested_but_no_destination", envp_id=envelope.id)
            return True  # Continue without encryption as fallback

        channel_opts: EncryptionOptions = {
            "encryption_type": "channel",
            "destination": envelope.to,
        }
        logger.debug(
            "forcing_channel_encryption",
            envp_id=envelope.id,
            destination=str(envelope.to),
        )
        return await self._handle_to_be_encrypted_envelope_with_options(envelope, context, channel_opts)
