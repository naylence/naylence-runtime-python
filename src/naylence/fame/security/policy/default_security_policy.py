"""
Default security policy implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Optional

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.core.protocol.frames import (
    KeyAnnounceFrame,
    KeyRequestFrame,
    NodeAttachFrame,
    NodeHeartbeatFrame,
    SecureAcceptFrame,
    SecureOpenFrame,
)
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.util.logging import getLogger

from ..encryption.encryption_manager import EncryptionOptions
from .security_policy import (
    CryptoLevel,
    EncryptionConfig,
    SecurityAction,
    SecurityPolicy,
    SecurityRequirements,
    SignaturePolicy,
    SigningConfig,
    SigningMaterial,
)

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike

logger = getLogger(__name__)


class DefaultSecurityPolicy(SecurityPolicy):
    """Default security policy implementation with flexible crypto configuration."""

    def __init__(
        self,
        *,
        # Custom policy functions (for advanced use cases)
        custom_signing_policy: Optional[
            Callable[[FameEnvelope, Optional[FameDeliveryContext]], bool]
        ] = None,
        custom_encryption_policy: Optional[
            Callable[[FameEnvelope, Optional[FameDeliveryContext]], bool]
        ] = None,
        # Flexible crypto configuration
        encryption: Optional[EncryptionConfig] = None,
        signing: Optional[SigningConfig] = None,
        key_provider: Optional[KeyProvider] = None,
    ):
        self.custom_signing_policy = custom_signing_policy
        self.custom_encryption_policy = custom_encryption_policy

        # Flexible crypto configuration
        self.encryption = encryption or EncryptionConfig.for_development()
        self.signing = signing or SigningConfig.for_development()
        self._key_provider = key_provider

    async def should_sign_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should be signed."""
        # Use custom policy if provided
        if self.custom_signing_policy:
            return self.custom_signing_policy(envelope, context)

        # Already signed
        if envelope.sec and envelope.sec.sig:
            return False

        # Special case: If we're going to encrypt this envelope, it MUST be signed for security
        # EXCEPT for responses where signature mirroring is explicitly disabled
        should_encrypt = await self.should_encrypt_envelope(envelope, context, node_like)
        if should_encrypt:
            # Check if this is a response with signature mirroring disabled
            is_response = self._is_response_envelope(envelope, context)
            if is_response and not self.signing.response.mirror_request_signing:
                # For responses with mirroring disabled, respect the mirroring setting
                # even if it means encrypting without signing (this is a policy choice)
                logger.debug(
                    "envelope_encryption_without_signing_due_to_disabled_mirroring",
                    envelope_id=envelope.id,
                    reason="response_signature_mirroring_disabled",
                )
            else:
                # For all other cases, encryption requires signing for security
                logger.debug(
                    "envelope_requires_signing_due_to_encryption",
                    envelope_id=envelope.id,
                    reason="outbound_encryption_requires_signing",
                )
                return True

        # Use signing configuration to decide
        if self._is_response_envelope(envelope, context):
            return self._should_sign_response(envelope, context, node_like)
        else:
            return self._should_sign_outbound_request(envelope, context, node_like)

    async def should_encrypt_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should be encrypted.

        SECURITY: Only encrypt envelopes from LOCAL origins to prevent remote exploitation.
        """

        # SECURITY CHECK: Only encrypt locally-originated envelopes
        if not context or context.origin_type != DeliveryOriginType.LOCAL:
            return False

        # Use custom policy if provided
        if self.custom_encryption_policy:
            return self.custom_encryption_policy(envelope, context)

        # Already encrypted
        if envelope.sec and envelope.sec.enc:
            return False

        # Use flexible crypto configuration to decide if we should encrypt
        # Decide crypto level based on whether this is a response or outbound request
        if self._is_response_envelope(envelope, context):
            # For responses, use the request's crypto level and response rules
            if context and context.security and hasattr(context.security, "inbound_crypto_level"):
                request_crypto_level = context.security.inbound_crypto_level or CryptoLevel.PLAINTEXT
            else:
                request_crypto_level = CryptoLevel.PLAINTEXT
            desired_level = await self.decide_response_crypto_level(request_crypto_level, envelope, context)
        else:
            # For new outbound requests, use outbound rules
            desired_level = await self.decide_outbound_crypto_level(envelope, context, node_like)
        return desired_level in [CryptoLevel.SEALED, CryptoLevel.CHANNEL]

    async def get_encryption_options(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> Optional[EncryptionOptions]:
        """Get encryption options for the envelope."""
        if not envelope.to:
            logger.debug("no_encryption_options_no_recipient", envelope_id=envelope.id)
            return None

        # Check if channel encryption should be used
        should_use_channel = await self._should_use_channel_encryption_internal(
            envelope, context, node_like
        )
        logger.debug(
            "encryption_decision_debug",
            envelope_id=envelope.id,
            should_use_channel=should_use_channel,
            context_meta=context.meta if context else None,
            has_context=context is not None,
            context_inbound_level=(
                context.security.inbound_crypto_level if context and context.security else None
            ),
            context_origin=context.origin_type if context else None,
        )

        if should_use_channel:
            logger.debug(
                "using_channel_encryption",
                envelope_id=envelope.id,
                recipient=str(envelope.to),
            )
            return {"encryption_type": "channel", "destination": envelope.to}

        try:
            # Try to look up the recipient's encryption key
            recip_kid, recip_pub_bytes = await self._lookup_recipient_encryption_key(
                envelope.to, node_like.physical_path if node_like else None
            )
            logger.debug(
                "found_encryption_key_for_recipient",
                envelope_id=envelope.id,
                recipient_key_id=recip_kid,
                recipient=str(envelope.to),
            )
            return EncryptionOptions(recip_kid=recip_kid, recip_pub=recip_pub_bytes)
        except Exception as e:
            # If we can't find the recipient's key locally, return special encryption options
            # that indicate a key should be requested by address
            logger.debug(
                "encryption_key_not_found_locally_will_request_by_address",
                envelope_id=envelope.id,
                recipient=str(envelope.to),
                error=str(e),
            )

            # Return special encryption options that indicate an address-based key request is needed
            # The key management system will detect this and send a KeyRequest with the address field
            return {"request_address": envelope.to}  # Address to request key for

    async def _lookup_recipient_encryption_key(
        self, address: FameAddress, node_physical_path: Optional[str] = None
    ) -> tuple[str, bytes]:
        if not address:
            raise ValueError("No recipient address in envelope")

        assert self._key_provider, "Key provider must be set for encryption key lookup"

        """Look up the recipient's encryption key and return (kid, public_key_bytes)."""
        from naylence.fame.core.address.address import parse_address

        logger.debug("starting_recipient_encryption_key_lookup", address=str(address))

        try:
            # Parse the address to get participant and path
            participant, path = parse_address(str(address))
            logger.debug("parsed_address", participant=participant, path=path)

            if not participant:
                raise ValueError(f"Cannot determine participant from address {address}")

            # Check if this is a local address (same physical path as this node)
            if path == node_physical_path:
                logger.debug(
                    "address_is_local_checking_node_crypto_provider",
                    node_path=node_physical_path,
                    address_path=path,
                )
                crypto_provider = get_crypto_provider()
                # Try to get the node's own encryption key from its crypto provider
                if crypto_provider.encryption_public_pem:
                    try:
                        from cryptography.hazmat.primitives import serialization

                        # Load the public key from PEM
                        pub_key = serialization.load_pem_public_key(
                            crypto_provider.encryption_public_pem.encode()
                        )

                        # Extract raw bytes for X25519
                        pub_bytes = pub_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw,
                        )
                        kid = crypto_provider.encryption_key_id

                        logger.debug(
                            "found_local_node_encryption_key",
                            kid=kid,
                            pub_key_length=len(pub_bytes),
                        )
                        return kid, pub_bytes
                    except Exception as e:
                        logger.debug("failed_to_extract_node_encryption_key", error=str(e))

            # Get the key store and look for any encryption keys for this address
            # key_store = get_key_store()
            # logger.debug("got_key_store", key_store_type=type(key_store).__name__)

            # First, try to find keys by looking up the address string directly
            address_str = str(address)
            keys = list(await self._key_provider.get_keys_for_path(address_str))
            logger.debug("found_keys_for_address", key_count=len(keys), address=address_str)

            if not keys:
                path_keys = list(await self._key_provider.get_keys_for_path(path))
                if path_keys:
                    logger.debug("found_keys_for_path", key_count=len(path_keys), path=path)
                    keys.extend(path_keys)

            # If no keys found for the full address, try looking for keys by participant name
            if not keys:
                participant_keys = list(await self._key_provider.get_keys_for_path(participant))
                if participant_keys:
                    logger.debug(
                        "found_keys_for_participant",
                        key_count=len(participant_keys),
                        participant=participant,
                    )
                    keys.extend(participant_keys)

            # Look through all found keys for encryption keys
            for i, key in enumerate(keys):
                kid = key.get("kid", "")
                use = key.get("use", "")
                kty = key.get("kty", "")
                crv = key.get("crv", "")
                logger.debug("examining_key", key_index=i, kid=kid, use=use, kty=kty, crv=crv)

                # Only consider keys explicitly marked for encryption
                if key.get("use") == "enc":
                    logger.debug("found_encryption_key_candidate", kid=kid)
                    # Found an encryption key, validate it's the right type
                    if key.get("kty") == "OKP" and key.get("crv") == "X25519":
                        # X25519 JWK format
                        from base64 import urlsafe_b64decode

                        from ..crypto.jwk_validation import (
                            JWKValidationError,
                            validate_encryption_key,
                        )

                        try:
                            # Validate that this is a proper encryption key
                            validate_encryption_key(key)
                        except JWKValidationError as e:
                            logger.warning("invalid_encryption_key", kid=kid, error=str(e))
                            continue

                        x_b64 = key.get("x", "")
                        if not x_b64:
                            logger.warning("encryption_key_missing_x_parameter", kid=kid)
                            continue

                        # Add padding if necessary
                        x_b64 += "=" * (-len(x_b64) % 4)
                        pub_bytes = urlsafe_b64decode(x_b64)
                        logger.debug(
                            "successfully_extracted_public_key",
                            kid=kid,
                            pub_key_length=len(pub_bytes),
                        )
                        return kid, pub_bytes
                    else:
                        logger.debug(
                            "skipping_unsupported_encryption_key_type",
                            kid=kid,
                            kty=kty,
                            crv=crv,
                            reason="not_x25519",
                        )
                else:
                    logger.debug("skipping_non_encryption_key", kid=kid, use=use)

            # No encryption key found locally - this will trigger an address-based key request
            error_msg = f"No encryption key found for address {address}"
            logger.debug(
                "no_local_encryption_key_found_will_request_from_upstream",
                address=address_str,
                participant=participant,
                available_keys=[k.get("kid", "unknown") for k in keys],
            )
            raise ValueError(error_msg)

        except Exception as e:
            logger.debug(
                "encryption_key_lookup_failed_will_trigger_request",
                address=str(address),
                error=str(e),
            )
            # Re-raise the exception to trigger the key request mechanism
            raise ValueError(f"Failed to lookup recipient key for {address}: {e}")

    async def should_verify_signature(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        """Determine if an envelope's signature should be verified."""
        rules = self.signing.inbound

        # If there's no signature
        if not (envelope.sec and envelope.sec.sig):
            # Check if signatures are required
            if rules.signature_policy == SignaturePolicy.REQUIRED:
                logger.warning(
                    "unsigned_envelope_but_signatures_required",
                    envelope_id=envelope.id,
                    action=rules.unsigned_violation_action.name,
                )
            return False  # Can't verify what doesn't exist

        # Determine verification based on policy
        if rules.signature_policy == SignaturePolicy.REQUIRED:
            return True  # Always verify when required
        elif rules.signature_policy == SignaturePolicy.OPTIONAL:
            return True  # Verify if present
        elif rules.signature_policy == SignaturePolicy.DISABLED:
            return False  # Don't verify even if present
        elif rules.signature_policy == SignaturePolicy.FORBIDDEN:
            # This would be handled as a violation in is_signature_required
            return False

        # Default: verify if configured to do so (backward compatibility)
        return True

    async def should_decrypt_envelope(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should be decrypted."""
        # Don't attempt to decrypt if there's no encryption
        if not (envelope.sec and envelope.sec.enc):
            return False

        # Only decrypt if we have a destination and it's local to this node
        if envelope.to:
            # Check if the destination is a local binding
            if self._is_local_address(envelope.to, node_like):
                logger.debug(
                    "should_decrypt_envelope_local",
                    envelope_id=envelope.id,
                    destination=str(envelope.to),
                    reason="destination_is_local_binding",
                )
                return True
            else:
                logger.debug(
                    "should_not_decrypt_envelope_forwarding",
                    envelope_id=envelope.id,
                    destination=str(envelope.to),
                    reason="destination_not_local_forwarding_only",
                )
                return False

        # Fallback: if no destination specified, decrypt by default for security
        logger.debug(
            "should_decrypt_envelope_fallback",
            envelope_id=envelope.id,
            reason="no_destination_using_default_policy",
        )
        return True

    async def _should_use_channel_encryption_internal(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an envelope should use channel encryption."""
        from naylence.fame.core import DeliveryOriginType

        # SECURITY CHECK: Only encrypt locally-originated envelopes
        if not context or context.origin_type != DeliveryOriginType.LOCAL:
            logger.debug(
                "channel_encryption_rejected_non_local",
                envelope_id=envelope.id,
                has_context=context is not None,
                origin=getattr(context, "origin_type", None),
            )
            return False

        # Only apply to DataFrames
        if not envelope.frame or envelope.frame.type != "Data":
            logger.debug(
                "channel_encryption_rejected_non_data",
                envelope_id=envelope.id,
                frame_type=getattr(envelope.frame, "type", None),
            )
            return False

        # Don't use channel encryption if envelope is already encrypted at the envelope level
        if envelope.sec and envelope.sec.enc:
            logger.debug("channel_encryption_rejected_already_encrypted", envelope_id=envelope.id)
            return False

        # Use flexible crypto configuration to decide if we should use channel encryption
        # Check if this is a response envelope - use context meta for message-type
        message_type = None
        if context and context.meta:
            message_type = context.meta.get("message-type")

        is_response = message_type in ["response", "protocol-response"]

        is_response = message_type in ["response", "protocol-response"]

        logger.debug(
            "channel_encryption_response_check",
            envelope_id=envelope.id,
            is_response=is_response,
            context_meta=context.meta if context else None,
            has_context=context is not None,
            context_inbound_crypto_level=(
                context.security.inbound_crypto_level if context and context.security else None
            ),
            mirror_request_level=self.encryption.response.mirror_request_level,
        )

        if is_response:
            # For responses, don't use channel encryption when mirroring SEALED requests
            # This preserves the same encryption method as the original request
            if (
                context
                and context.security
                and hasattr(context.security, "inbound_crypto_level")
                and context.security.inbound_crypto_level == CryptoLevel.SEALED
                and self.encryption.response.mirror_request_level
            ):
                logger.debug(
                    "channel_encryption_rejected_sealed_mirror",
                    envelope_id=envelope.id,
                    original_request_level=context.security.inbound_crypto_level,
                    mirror_enabled=self.encryption.response.mirror_request_level,
                )
                return False  # Use sealed envelope encryption like the original request

            # For other response cases, use outbound rules as fallback
            desired_level = await self.decide_outbound_crypto_level(envelope, context, node_like)
            logger.debug(
                "channel_encryption_response_fallback",
                envelope_id=envelope.id,
                desired_level=desired_level,
                result=desired_level == CryptoLevel.CHANNEL,
            )
            return desired_level == CryptoLevel.CHANNEL
        else:
            # For regular outbound messages, use outbound rules
            desired_level = await self.decide_outbound_crypto_level(envelope, context, node_like)
            logger.debug(
                "channel_encryption_outbound_decision",
                envelope_id=envelope.id,
                desired_level=desired_level,
                result=desired_level == CryptoLevel.CHANNEL,
            )
            return desired_level == CryptoLevel.CHANNEL

    def _is_local_address(self, address: FameAddress, node_like: Optional[NodeLike] = None) -> bool:
        """Check if an address is local to this node."""
        if node_like and hasattr(node_like, "has_local"):
            return node_like.has_local(address)
        return False

    def classify_message_crypto_level(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> CryptoLevel:
        """Classify the encryption level of an incoming message."""
        # Check if the envelope has encryption by inspecting the security header
        if envelope.sec and envelope.sec.enc:
            # Get the algorithm used for encryption
            alg = getattr(envelope.sec.enc, "alg", None)
            if alg:
                # Check if it's a channel encryption algorithm
                if alg in self.encryption.supported_channel_algorithms:
                    logger.debug(
                        "classified_as_channel_encryption",
                        envelope_id=envelope.id,
                        algorithm=alg,
                    )
                    return CryptoLevel.CHANNEL
                # Check if it's a sealed encryption algorithm
                elif alg in self.encryption.supported_sealed_algorithms:
                    logger.debug(
                        "classified_as_sealed_encryption",
                        envelope_id=envelope.id,
                        algorithm=alg,
                    )
                    return CryptoLevel.SEALED
                else:
                    # Unknown algorithm - log warning and treat as sealed for safety
                    logger.warning(
                        "unknown_encryption_algorithm",
                        envelope_id=envelope.id,
                        algorithm=alg,
                        supported_channel=self.encryption.supported_channel_algorithms,
                        supported_sealed=self.encryption.supported_sealed_algorithms,
                        defaulting_to="SEALED",
                    )
                    return CryptoLevel.SEALED
            else:
                # Encryption present but no algorithm specified - treat as sealed for safety
                logger.warning(
                    "encryption_present_but_no_algorithm",
                    envelope_id=envelope.id,
                    defaulting_to="SEALED",
                )
                return CryptoLevel.SEALED

        # Default to plaintext if no encryption indicators found
        logger.debug(
            "classified_as_plaintext",
            envelope_id=envelope.id,
            reason="no_encryption_headers",
        )
        return CryptoLevel.PLAINTEXT

    def is_inbound_crypto_level_allowed(
        self,
        crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> bool:
        """Check if an inbound message's crypto level is allowed by policy."""
        rules = self.encryption.inbound

        if crypto_level == CryptoLevel.PLAINTEXT:
            return rules.allow_plaintext
        elif crypto_level == CryptoLevel.CHANNEL:
            return rules.allow_channel
        elif crypto_level == CryptoLevel.SEALED:
            return rules.allow_sealed
        else:
            # Unknown crypto level - deny by default
            return False

    def get_inbound_violation_action(
        self,
        crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> SecurityAction:
        """Get the action to take when inbound crypto level violates policy."""
        rules = self.encryption.inbound

        if crypto_level == CryptoLevel.PLAINTEXT:
            return rules.plaintext_violation_action
        elif crypto_level == CryptoLevel.CHANNEL:
            return rules.channel_violation_action
        elif crypto_level == CryptoLevel.SEALED:
            return rules.sealed_violation_action
        else:
            # Unknown crypto level - default to NACK
            return SecurityAction.NACK

    async def decide_response_crypto_level(
        self,
        request_crypto_level: CryptoLevel,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> CryptoLevel:
        """Determine what crypto level to use for a response based on the original request."""

        if envelope.frame and not isinstance(envelope.frame, DataFrame):
            return CryptoLevel.PLAINTEXT  # Control frames should not be encrypted

        rules = self.encryption.response

        # If configured to escalate to SEALED for responses, try that first
        if rules.escalate_sealed_responses:
            return CryptoLevel.SEALED

        # Mirror the request level if configured
        if rules.mirror_request_level:
            response_level = request_crypto_level
        else:
            # Use minimum required level
            response_level = rules.minimum_response_level

        # Always ensure we meet the minimum security level
        # Even when mirroring, we should enforce the minimum as a security baseline
        if response_level < rules.minimum_response_level:
            response_level = rules.minimum_response_level

        return response_level

    async def decide_outbound_crypto_level(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> CryptoLevel:
        """Determine what crypto level to use for a new outbound request (not a response)."""

        if not isinstance(envelope.frame, DataFrame):
            return CryptoLevel.PLAINTEXT

        rules = self.encryption.outbound

        # Start with the default level
        crypto_level = rules.default_level

        # If configured to escalate for peer support, check if recipient has encryption keys
        if rules.escalate_if_peer_supports and envelope.to:
            try:
                # Try to lookup recipient's encryption key
                await self._lookup_recipient_encryption_key(
                    envelope.to, node_like.physical_path if node_like else None
                )
                # If we found a key, we can use SEALED encryption
                crypto_level = CryptoLevel.SEALED
            except Exception:
                # No key found, stick with default level
                pass

        # If configured to prefer SEALED for sensitive operations
        if rules.prefer_sealed_for_sensitive:
            # Check if this is a sensitive operation (this is application-specific logic)
            if self._is_sensitive_operation(envelope):
                crypto_level = CryptoLevel.SEALED

        return crypto_level

    def _is_sensitive_operation(self, envelope: FameEnvelope) -> bool:
        """Determine if an envelope represents a sensitive operation that should use higher encryption."""
        # This is a placeholder for application-specific logic
        # In practice, this could check:
        # - RPC method names (e.g., anything with "auth", "key", "secret" in the name)
        # - Envelope metadata tags
        # - Destination addresses (certain services might be sensitive)
        # - Payload content analysis

        # For now, default to False (not sensitive)
        # Applications can override this method for custom logic
        return False

    def _is_response_envelope(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        """Check if an envelope is a response to a previous request."""
        # Check context meta for message-type
        message_type = None
        if context and context.meta:
            message_type = context.meta.get("message-type")

        # Check for response metadata
        if message_type == "response":
            return True

        # Check for protocol responses
        if message_type == "protocol-response":
            return True

        return False

    def _should_sign_response(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if a response envelope should be signed."""
        rules = self.signing.response

        # Always sign responses if configured
        if rules.always_sign_responses:
            return True

        # Sign error responses if configured
        if rules.sign_error_responses:
            # Check if this is an error response (could check status codes, error frames, etc.)
            if self._is_error_response(envelope):
                return True

        # Mirror request signing if configured
        if rules.mirror_request_signing:
            # Check if the original request was signed
            if context and context.security:
                # First check if we have explicit signature tracking
                if hasattr(context.security, "inbound_was_signed") and context.security.inbound_was_signed:
                    logger.debug(
                        "mirroring_signature_due_to_signed_request",
                        envelope_id=envelope.id,
                        reason="inbound_request_was_signed",
                    )
                    return True

                # Fallback: Check if the original request had security
                # (indicated by non-plaintext crypto level)
                # This handles cases where inbound_was_signed might not be available
                elif (
                    hasattr(context.security, "inbound_crypto_level")
                    and context.security.inbound_crypto_level
                    and context.security.inbound_crypto_level != CryptoLevel.PLAINTEXT
                ):
                    logger.debug(
                        "mirroring_signature_due_to_encrypted_request",
                        envelope_id=envelope.id,
                        reason="inbound_request_was_encrypted",
                        crypto_level=context.security.inbound_crypto_level.name,
                    )
                    return True

        return False

    def _should_sign_outbound_request(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        node_like: Optional[NodeLike] = None,
    ) -> bool:
        """Determine if an outbound request envelope should be signed."""
        rules = self.signing.outbound

        # Sign sensitive operations if configured
        if rules.sign_sensitive_operations and self._is_sensitive_operation(envelope):
            return True

        # Sign if recipient expects signatures (would need recipient policy lookup)
        if rules.sign_if_recipient_expects:
            # This is placeholder logic - in reality you'd lookup the recipient's policy
            # For now, assume recipients expect signatures
            return True

        # Use default signing policy
        return rules.default_signing

    def _is_error_response(self, envelope: FameEnvelope) -> bool:
        """Check if an envelope represents an error response."""
        # Check frame type for error frames - this is the primary way to detect errors
        if envelope.frame and hasattr(envelope.frame, "type"):
            if envelope.frame.type == "Error":
                return True

        # Additional checks could be added here for other error indicators:
        # - RPC error responses in frame payload
        # - HTTP error status codes in frame metadata
        # - Application-specific error indicators

        return False

    def is_signature_required(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> bool:
        """Check if an inbound message must have a signature."""
        # Mandatory signature enforcement for critical security frames

        # These frames must ALWAYS be signed regardless of policy configuration
        if isinstance(
            envelope.frame,
            KeyRequestFrame | KeyAnnounceFrame | SecureOpenFrame | SecureAcceptFrame,
        ):
            return True

        if isinstance(envelope.frame, NodeAttachFrame | NodeHeartbeatFrame):
            return False

        rules = self.signing.inbound

        # Check signature requirements based on policy
        if rules.signature_policy == SignaturePolicy.REQUIRED:
            return True
        elif rules.signature_policy == SignaturePolicy.FORBIDDEN:
            # Special case: if message is signed but policy forbids it, this is also a
            # "requirement" violation
            has_signature = bool(envelope.sec and envelope.sec.sig)
            return has_signature  # Return True if signed (violation), False if unsigned (OK)
        else:
            return False  # OPTIONAL or DISABLED don't require signatures

    def get_unsigned_violation_action(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> SecurityAction:
        """Get the action to take when a required signature is missing."""
        return self.signing.inbound.unsigned_violation_action

    def get_invalid_signature_violation_action(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> SecurityAction:
        """Get the action to take when signature verification fails."""
        return self.signing.inbound.invalid_signature_action

    def requirements(self) -> SecurityRequirements:
        """Get the security requirements of this policy."""

        # Analyze the policy configuration to determine requirements
        signing_required = False
        verification_required = False
        encryption_required = False
        decryption_required = False

        # Check if signing is required based on signing configuration
        if (
            self.signing.outbound.default_signing
            or self.signing.outbound.sign_sensitive_operations
            or self.signing.response.mirror_request_signing  # Need signer for mirroring!
            or self.signing.response.always_sign_responses
            or self.signing.response.sign_error_responses
        ):
            signing_required = True

        # Check if verification is needed based on inbound signature policy
        # We need verification capability unless signatures are completely disabled/forbidden
        if self.signing.inbound.signature_policy in [
            SignaturePolicy.REQUIRED,
            SignaturePolicy.OPTIONAL,
        ]:
            verification_required = True

        # Check if encryption is required based on encryption configuration
        if self.encryption.outbound.default_level in [
            CryptoLevel.SEALED,
            CryptoLevel.CHANNEL,
        ] or self.encryption.response.minimum_response_level in [
            CryptoLevel.SEALED,
            CryptoLevel.CHANNEL,
        ]:
            encryption_required = True

        if self.encryption.inbound.allow_sealed or self.encryption.inbound.allow_channel:
            decryption_required = True

        # # Key exchange is required if we need sealed encryption (end-to-end) OR signing
        # # Channel encryption (TLS) doesn't require key exchange as it's handled by the transport layer
        # # Signing requires key exchange for key distribution and verification
        # if (
        #     self.encryption.outbound.default_level == CryptoLevel.SEALED
        #     or self.encryption.response.minimum_response_level == CryptoLevel.SEALED
        #     or self.encryption.inbound.allow_sealed
        #     or signing_required
        #     or verification_required
        # ):
        #     require_key_exchange = True

        # Granular key exchange requirements
        # Key exchange is only required when we need to SEND encrypted messages or signatures
        # not just when we can receive them
        require_signing_key_exchange = signing_required  # Only when we need to sign outbound messages

        require_encryption_key_exchange = encryption_required or decryption_required

        # Determine minimum crypto level from policy
        min_level = CryptoLevel.PLAINTEXT
        if not self.encryption.inbound.allow_plaintext:
            if self.encryption.inbound.allow_channel:
                min_level = CryptoLevel.CHANNEL
            elif self.encryption.inbound.allow_sealed:
                min_level = CryptoLevel.SEALED

        # Check if certificate manager is required based on signing material
        require_certificates = self.signing.signing_material == SigningMaterial.X509_CHAIN

        return SecurityRequirements(
            signing_required=signing_required,
            verification_required=verification_required,
            encryption_required=encryption_required,
            decryption_required=decryption_required,
            require_key_exchange=require_signing_key_exchange or require_encryption_key_exchange,
            require_signing_key_exchange=require_signing_key_exchange,
            require_encryption_key_exchange=require_encryption_key_exchange,
            require_node_authorization=True,  # Default security policy enables node authorization
            require_certificates=require_certificates,
            minimum_crypto_level=min_level,
            supported_signing_algorithms=frozenset(["EdDSA"]),
            supported_encryption_algorithms=frozenset(
                self.encryption.supported_sealed_algorithms + self.encryption.supported_channel_algorithms
            ),
            # New list-based preferences
            preferred_signing_algorithms=["EdDSA"],
            preferred_encryption_algorithms=["X25519", "ChaCha20Poly1305"],
            # Backward compatibility
            preferred_signing_algorithm="EdDSA",
            preferred_encryption_algorithm="X25519",
        )
