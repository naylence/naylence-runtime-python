from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.encryption.encryption_manager import EncryptionManager
from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.security.policy import SecurityPolicy
from naylence.fame.security.security_manager import SecurityManager
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.node.admission.node_attach_client import AttachInfo
    from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
    from naylence.fame.node.node_like import NodeLike
    from naylence.fame.node.secure_channel_frame_handler import (
        SecureChannelFrameHandler,
    )
    from naylence.fame.security.cert.certificate_manager import CertificateManager
    from naylence.fame.security.encryption.secure_channel_manager import (
        SecureChannelManager,
    )
    from naylence.fame.security.keys.key_management_handler import KeyManagementHandler
    from naylence.fame.security.keys.key_manager import KeyManager

logger = getLogger(__name__)


class DefaultSecurityManager(SecurityManager):
    """
    Single bundle for all node security components.

    policy              - declarative security rules
    envelope_signer     - used for outbound envelopes (may be None if not required)
    envelope_verifier   - used for inbound envelopes (may be None if not required)
    encryption          - EncryptionManager chosen for this node (may be None)
    key_manager         - KeyManager for key exchange and management (may be None)
    authorizer          - NodeAttachAuthorizer for sentinel nodes (may be None for regular nodes)
    certificate_manager - CertificateManager for policy-driven certificate provisioning (may be None)
    envelope_security_handler - Handler for envelope security operations (created on node start)
    secure_channel_manager     - Manager for secure channels (created on node start)
    secure_channel_frame_handler - Handler for channel frames (created on node start)
    """

    def __init__(
        self,
        policy: SecurityPolicy,
        envelope_signer: Optional[EnvelopeSigner] = None,
        envelope_verifier: Optional[EnvelopeVerifier] = None,
        encryption: Optional[EncryptionManager] = None,
        key_manager: Optional[KeyManager] = None,
        authorizer: Optional[Authorizer] = None,
        certificate_manager: Optional[CertificateManager] = None,
        secure_channel_manager: Optional[SecureChannelManager] = None,
        key_validator: Optional[AttachmentKeyValidator] = None,
    ):
        self._policy = policy
        self._envelope_signer = envelope_signer
        self._envelope_verifier = envelope_verifier
        self._encryption = encryption
        self._key_manager = key_manager
        self._authorizer = authorizer
        self._certificate_manager = certificate_manager
        self._key_validator = key_validator

        # These will be created during on_node_started
        self._envelope_security_handler: Optional[EnvelopeSecurityHandler] = None
        self._secure_channel_manager: Optional[SecureChannelManager] = secure_channel_manager
        self._secure_channel_frame_handler: Optional[SecureChannelFrameHandler] = None
        self._key_management_handler: Optional[KeyManagementHandler] = None  # Created on node start

        from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler

        self._key_frame_handler: Optional[KeyFrameHandler] = None

    @property
    def priority(self) -> int:
        return 2000

    # Property implementations
    @property
    def policy(self) -> SecurityPolicy:
        """Get the security policy."""
        return self._policy

    @policy.setter
    def policy(self, value: SecurityPolicy) -> None:
        """Set the security policy."""
        self._policy = value

    @property
    def envelope_signer(self) -> Optional[EnvelopeSigner]:
        """Get the envelope signer."""
        return self._envelope_signer

    @envelope_signer.setter
    def envelope_signer(self, value: Optional[EnvelopeSigner]) -> None:
        """Set the envelope signer."""
        self._envelope_signer = value

    @property
    def envelope_verifier(self) -> Optional[EnvelopeVerifier]:
        """Get the envelope verifier."""
        return self._envelope_verifier

    @envelope_verifier.setter
    def envelope_verifier(self, value: Optional[EnvelopeVerifier]) -> None:
        """Set the envelope verifier."""
        self._envelope_verifier = value

    @property
    def encryption(self) -> Optional[EncryptionManager]:
        """Get the encryption manager."""
        return self._encryption

    @encryption.setter
    def encryption(self, value: Optional[EncryptionManager]) -> None:
        """Set the encryption manager."""
        self._encryption = value

    @property
    def key_manager(self) -> Optional[KeyManager]:
        """Get the key manager."""
        return self._key_manager

    @key_manager.setter
    def key_manager(self, value: Optional[KeyManager]) -> None:
        """Set the key manager."""
        self._key_manager = value

    @property
    def authorizer(self) -> Optional[Authorizer]:
        """Get the node attach authorizer."""
        return self._authorizer

    @authorizer.setter
    def authorizer(self, value: Optional[Authorizer]) -> None:
        """Set the node attach authorizer."""
        self._authorizer = value

    @property
    def certificate_manager(self) -> Optional[CertificateManager]:
        """Get the certificate manager."""
        return self._certificate_manager

    @certificate_manager.setter
    def certificate_manager(self, value: Optional[CertificateManager]) -> None:
        """Set the certificate manager."""
        self._certificate_manager = value

    @property
    def envelope_security_handler(self) -> Optional[EnvelopeSecurityHandler]:
        """Get the envelope security handler."""
        return self._envelope_security_handler

    @property
    def secure_channel_frame_handler(self) -> Optional[SecureChannelFrameHandler]:
        """Get the channel frame handler."""
        return self._secure_channel_frame_handler

    async def on_node_started(self, node: NodeLike) -> None:
        """
        Handle node initialization for all security components.

        This method implements the NodeEventListener interface and dispatches
        the node started event to all relevant security components. It also
        creates the envelope security handler and channel components.

        Args:
            node: The node that has been started
        """
        # Dispatch events to components that implement NodeEventListener
        if self._certificate_manager:
            await self._certificate_manager.on_node_started(node)

        if self._encryption and isinstance(self._encryption, NodeEventListener):
            await self._encryption.on_node_started(node)

        # Start key manager if present
        if self._key_manager is not None:
            await self._key_manager.on_node_started(node)

        # Create envelope security handler
        # Create channel manager for secure channel encryption
        from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
        from naylence.fame.node.secure_channel_frame_handler import (
            SecureChannelFrameHandler,
        )
        from naylence.fame.security.keys.key_management_handler import (
            KeyManagementHandler,
        )

        # Create and start the key management handler if we have key management
        if self._key_manager is not None and self.supports_overlay_security:
            assert self._key_validator, "Key validator must be set"
            self._key_management_handler = KeyManagementHandler(
                node_like=node,
                key_manager=self._key_manager,
                encryption_manager=self._encryption,
                key_validator=self._key_validator,
            )
            await self._key_management_handler.start()

        # Only create envelope security handler if we have a key management handler
        # The EnvelopeSecurityHandler requires a KeyManagementHandler
        if self._key_management_handler is not None:
            self._envelope_security_handler = EnvelopeSecurityHandler(
                node_like=node,
                envelope_signer=self._envelope_signer,
                envelope_verifier=self._envelope_verifier,
                encryption_manager=self._encryption,
                security_policy=self._policy,
                key_management_handler=self._key_management_handler,
            )

        # Create a wrapper for the send callback to provide proper context
        async def send_with_context(envelope, context=None):
            """Send envelope using node's deliver method with provided context or LOCAL context."""
            if context is None:
                context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id=node.id)
            await node.deliver(envelope, context)

        if self.supports_overlay_security:
            self._secure_channel_frame_handler = SecureChannelFrameHandler(
                secure_channel_manager=self._secure_channel_manager,
                envelope_factory=node.envelope_factory,
                send_callback=send_with_context,
                envelope_security_handler=self._envelope_security_handler,
            )

        # Create KeyFrameHandler for Sentinel nodes to handle KeyRequest frames
        # Check if this is a Sentinel node by looking for routing capabilities
        if self.supports_overlay_security and isinstance(node, RoutingNodeLike):
            from typing import cast

            from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler

            routing_node = cast(RoutingNodeLike, node)

            self._key_frame_handler = KeyFrameHandler(
                routing_node=routing_node,
                route_manager=getattr(node, "_route_manager"),
                binding_manager=getattr(node, "_binding_manager"),
                accept_key_announce_parent=self._get_key_announce_handler(),
                key_manager=self._key_manager,
            )

            # Start the key frame handler - check for spawner method
            spawner = getattr(node, "spawn", None) or getattr(routing_node, "spawn", None)
            if spawner:
                await self._key_frame_handler.start(spawner)
            else:
                logger.warning("no_spawner_available_for_key_frame_handler", node_id=node.id)

            logger.debug("key_frame_handler_created_for_sentinel", node_id=node.id)

        logger.debug(
            "security_components_initialized",
            node_id=node.id,
            has_certificate_manager=bool(self._certificate_manager),
            has_encryption=bool(self._encryption),
            has_key_manager=bool(self._key_manager),
            has_envelope_security_handler=bool(self._envelope_security_handler),
            has_secure_channel_manager=bool(self._secure_channel_manager),
        )

    @property
    def supports_overlay_security(self) -> bool:
        return self._envelope_signer is not None or self._envelope_verifier is not None

    async def on_node_attach_to_upstream(self, node: NodeLike, attach_info: AttachInfo) -> None:
        """
        Handle parent key management and security validation when attaching to upstream.

        This method processes parent keys, validates security policy compatibility,
        and manages key exchange requirements during node attachment.
        """
        from naylence.fame.core import DeliveryOriginType

        # Validate security policy compatibility with parent keys
        if parent_keys := attach_info.get("parent_keys"):
            # Validate that the provided keys meet our security policy requirements
            is_valid, reason = self._policy.validate_attach_security_compatibility(
                peer_keys=parent_keys,
                peer_requirements=None,  # We don't know parent's requirements yet
                node_like=node,
            )

            if not is_valid:
                logger.error(
                    "attach_security_validation_failed",
                    reason=reason,
                    parent_system_id=attach_info.get("target_system_id"),
                    provided_keys_count=len(parent_keys),
                )
                # Note: In a more strict implementation, we might want to close the connection here
                # For now, we log the error but continue - this maintains backward compatibility
                # while providing visibility into security policy violations
            else:
                logger.debug(
                    "attach_security_validation_passed",
                    parent_system_id=attach_info.get("target_system_id"),
                    provided_keys_count=len(parent_keys),
                )

            # Accept parent key only, filter by target_system_id
            # TODO: rename target_system_id to parent_system_id ?
            if self._key_manager is not None:
                await self._key_manager.add_keys(
                    keys=parent_keys,
                    physical_path=attach_info["target_physical_path"],
                    system_id=attach_info["target_system_id"],
                    origin=DeliveryOriginType.UPSTREAM,
                )
            else:
                logger.debug("skipping_parent_keys_no_key_manager")
        else:
            # No parent keys provided - validate if our policy requires them
            requirements = self._policy.requirements()
            if requirements.require_signing_key_exchange or requirements.require_encryption_key_exchange:
                logger.warning(
                    "attach_missing_required_keys",
                    require_signing_keys=requirements.require_signing_key_exchange,
                    require_encryption_keys=requirements.require_encryption_key_exchange,
                    parent_system_id=attach_info.get("target_system_id"),
                )
                # Note: In a more strict implementation, we might want to close the connection here

        # Retry any pending key requests that were skipped during attachment
        # (now that both physical_path and sid are available)
        key_management_handler = getattr(node, "_key_management_handler", None)
        if key_management_handler:
            await key_management_handler.retry_pending_key_requests_after_attachment()

        if self._encryption and isinstance(self._encryption, NodeEventListener):
            await self._encryption.on_node_attach_to_upstream(node, attach_info)

        logger.debug(
            "node_attach_security_processed",
            node_id=node.id,
            parent_system_id=attach_info.get("target_system_id"),
            parent_keys_count=len(attach_info.get("parent_keys") or []),
        )

    async def on_node_initialized(self, node: NodeLike) -> None:
        """
        Handle security manager initialization after full node construction.

        This method is called after the node has been fully constructed,
        including all sub-components like routing capabilities, but before
        the node actually starts operating. This is the ideal place to:
        - Update key manager context with routing capabilities
        - Perform final configuration based on node capabilities
        - Set up cross-component dependencies

        Args:
            node: The node that has been initialized
        """
        # Initialize key manager if present
        if self._key_manager is not None:
            await self._key_manager.on_node_initialized(node)
            logger.debug("key_manager_initialized", node_id=node.id)

        # Dispatch init event to other security components that implement NodeEventListener
        if self._certificate_manager and isinstance(self._certificate_manager, NodeEventListener):
            await self._certificate_manager.on_node_initialized(node)

        if self._encryption and isinstance(self._encryption, NodeEventListener):
            await self._encryption.on_node_initialized(node)

        logger.debug("node_security_initialization_complete", node_id=node.id)

    async def on_node_attach_to_peer(
        self, node: NodeLike, attach_info: AttachInfo, connector: FameConnector
    ) -> None:
        """
        Handle peer key management when attaching to a peer.

        This method processes peer keys and manages key exchange requirements
        during peer attachment. It handles the logic that was previously in
        Sentinel._on_node_attach_to_peer.

        Args:
            node: The sentinel node that attached to the peer
            attach_info: The attachment information received from peer
            connector: The connector used for peer communication
        """
        from naylence.fame.core import DeliveryOriginType

        if peer_keys := attach_info.get("parent_keys"):
            if self._key_manager is not None:
                await self._key_manager.add_keys(
                    keys=peer_keys,
                    physical_path=attach_info["target_physical_path"],
                    system_id=attach_info["target_system_id"],
                    origin=DeliveryOriginType.PEER,
                )
                logger.debug(
                    "peer_keys_added",
                    peer_system_id=attach_info["target_system_id"],
                    peer_keys_count=len(peer_keys),
                )
            else:
                logger.debug("skipping_peer_keys_no_key_manager")
        else:
            logger.debug(
                "no_peer_keys_provided",
                peer_system_id=attach_info.get("target_system_id"),
            )

        # Dispatch peer attach event to other security components that implement NodeEventListener
        if self._certificate_manager and isinstance(self._certificate_manager, NodeEventListener):
            await self._certificate_manager.on_node_attach_to_peer(node, attach_info, connector)

        if self._encryption and isinstance(self._encryption, NodeEventListener):
            await self._encryption.on_node_attach_to_peer(node, attach_info, connector)

    async def on_deliver_local(
        self,
        node: NodeLike,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle all security processing for local envelope delivery.

        This method centralizes all security-related logic for local delivery:
        - Security policy validation (crypto level, signature requirements)
        - Envelope and channel decryption
        - Channel frame handling (SecureOpen/Accept/Close)
        - Payload integrity verification
        - Context updates for channel encryption

        Args:
            node: The node performing local delivery
            address: The target address for delivery
            envelope: The envelope to be delivered
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt delivery
        """
        from naylence.fame.util.logging import getLogger
        from naylence.fame.util.util import secure_digest

        logger = getLogger(__name__)

        # Track if envelope was encrypted before decryption
        was_encrypted = envelope.sec and envelope.sec.enc is not None

        logger.debug(
            "deliver_local_security_processing",
            address=str(address),
            envp_id=envelope.id,
            was_encrypted=was_encrypted,
            has_signature=bool(envelope.sec and envelope.sec.sig),
        )

        # Skip security policy checks for system frames that are expected to be plaintext
        system_frames_exempt_from_crypto_policy = {
            "SecureOpen",
            "SecureAccept",
            "SecureClose",  # Channel handshake frames
            "DeliveryAck",  # Acknowledgment frames (including NACKs)
            "NodeHeartbeat",
            "NodeHeartbeatAck",  # Heartbeat frames
            "KeyAnnounce",
            "KeyRequest",  # Key management frames
            "AddressBind",
            "AddressUnbind",
            "AddressBindAck",
            "AddressUnbindAck",  # Binding frames
            "CapabilityAdvertise",
            "CapabilityWithdraw",
            "CapabilityAdvertiseAck",
            "CapabilityWithdrawAck",  # Capability frames
        }

        frame_type = envelope.frame.type
        is_system_frame = frame_type in system_frames_exempt_from_crypto_policy

        # Security policy validation
        if self._policy and not is_system_frame:
            context_inbound_crypto_level = (
                context.security.inbound_crypto_level if context and context.security else None
            )
            crypto_level = context_inbound_crypto_level or self._policy.classify_message_crypto_level(
                envelope, None
            )
            logger.debug(
                "inbound_crypto_level_classified",
                envp_id=envelope.id,
                crypto_level=crypto_level.name,
                address=str(address),
            )

            # Check crypto level policy
            if not self._policy.is_inbound_crypto_level_allowed(crypto_level, envelope, None):
                violation_action = self._policy.get_inbound_violation_action(crypto_level, envelope, None)
                logger.warning(
                    "inbound_crypto_level_violation",
                    envp_id=envelope.id,
                    crypto_level=crypto_level.name,
                    action=violation_action.name,
                    address=str(address),
                )

                from naylence.fame.security.policy.security_policy import SecurityAction

                if violation_action == SecurityAction.REJECT:
                    logger.error(
                        "inbound_message_rejected",
                        envp_id=envelope.id,
                        crypto_level=crypto_level.name,
                    )
                    return None  # Halt delivery
                elif violation_action == SecurityAction.NACK:
                    logger.error(
                        "inbound_message_nacked",
                        envp_id=envelope.id,
                        crypto_level=crypto_level.name,
                    )
                    await self._send_nack(node, envelope, reason="crypto_level_violation")
                    return None  # Halt delivery

            # Signature verification policy
            has_signature = bool(envelope.sec and envelope.sec.sig)
            if not has_signature:
                if self._policy.is_signature_required(envelope, None):
                    violation_action = self._policy.get_unsigned_violation_action(envelope, None)
                    logger.warning(
                        "inbound_signature_violation_unsigned",
                        envp_id=envelope.id,
                        action=violation_action.name,
                        address=str(address),
                    )

                    from naylence.fame.security.policy.security_policy import (
                        SecurityAction,
                    )

                    if violation_action == SecurityAction.REJECT:
                        logger.error("inbound_message_rejected_unsigned", envp_id=envelope.id)
                        return None  # Halt delivery
                    elif violation_action == SecurityAction.NACK:
                        logger.error("inbound_message_nacked_unsigned", envp_id=envelope.id)
                        await self._send_nack(node, envelope, reason="signature_required")
                        return None  # Halt delivery

            elif await self._policy.should_verify_signature(envelope, None):
                if self._envelope_verifier:
                    try:
                        await self._envelope_verifier.verify_envelope(envelope, check_payload=False)
                        logger.debug(
                            "inbound_signature_verified",
                            envp_id=envelope.id,
                            address=str(address),
                        )
                    except ValueError as e:
                        violation_action = self._policy.get_invalid_signature_violation_action(
                            envelope, None
                        )
                        logger.warning(
                            "inbound_signature_verification_failed",
                            envp_id=envelope.id,
                            error=str(e),
                            action=violation_action.name,
                            address=str(address),
                        )

                        from naylence.fame.security.policy.security_policy import (
                            SecurityAction,
                        )

                        if violation_action == SecurityAction.REJECT:
                            logger.error(
                                "inbound_message_rejected_invalid_signature",
                                envp_id=envelope.id,
                            )
                            return None  # Halt delivery
                        elif violation_action == SecurityAction.NACK:
                            logger.error(
                                "inbound_message_nacked_invalid_signature",
                                envp_id=envelope.id,
                            )
                            await self._send_nack(node, envelope, reason="signature_verification_failed")
                            return None  # Halt delivery

        # Envelope decryption
        if (
            self._envelope_security_handler
            and await self._envelope_security_handler.should_decrypt_envelope(envelope, None)
        ):
            logger.debug("deliver_local_decrypt_check", was_encrypted=was_encrypted)
            envelope = await self._envelope_security_handler.decrypt_envelope(envelope, opts=None)
            logger.debug(
                "deliver_local_after_decrypt",
                envp_id=envelope.id,
                frame_type=envelope.frame.type if envelope.frame else None,
            )

        # Handle channel handshake frames
        if envelope.frame.type == "SecureAccept":
            if self._secure_channel_frame_handler:
                await self._secure_channel_frame_handler.handle_secure_accept(envelope, None)
            return None  # Halt delivery (handled by frame handler)

        if envelope.frame.type == "SecureOpen":
            if self._secure_channel_frame_handler:
                await self._secure_channel_frame_handler.handle_secure_open(envelope, None)
            return None  # Halt delivery (handled by frame handler)

        if envelope.frame.type == "SecureClose":
            if self._secure_channel_frame_handler:
                await self._secure_channel_frame_handler.handle_secure_close(envelope, None)
            return None  # Halt delivery (handled by frame handler)

        # Payload integrity verification for signed DataFrames
        if envelope.sec and envelope.sec.sig and isinstance(envelope.frame, DataFrame):
            if was_encrypted:
                if envelope.frame.pd is None:
                    logger.warning("deliver_local_missing_payload_digest", envp_id=envelope.id)
            else:
                if envelope.frame.pd is None:
                    raise ValueError("DataFrame missing payload digest (pd field) for final delivery")

                from naylence.fame.security.signing.eddsa_signer_verifier import (
                    _canonical_json,
                )

                payload_str = (
                    _canonical_json(envelope.frame.payload) if envelope.frame.payload is not None else ""
                )
                # logger.trace(
                #     "computed_dataframe_payload_str",
                #     payload=payload_str,
                #     raw_payload=envelope.frame.payload,
                #     raw_payload_type=type(envelope.frame.payload),
                # )
                actual_payload_digest = secure_digest(payload_str)

                if envelope.frame.pd != actual_payload_digest:
                    logger.error(
                        "payload_digest_mismatch_details",
                        expected_pd=envelope.frame.pd,
                        actual_digest=actual_payload_digest,
                        frame_dict=envelope.frame.__dict__,
                    )
                    raise ValueError("Payload digest mismatch on final delivery")

                logger.debug(
                    "deliver_local_payload_verified",
                    expected_pd=envelope.frame.pd,
                    actual_digest=actual_payload_digest,
                )

        # Return the processed envelope for continued delivery
        logger.debug(
            "deliver_local_security_processing_complete",
            envp_id=envelope.id,
            address=str(address),
        )
        return envelope

    async def on_deliver(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle security processing for envelope delivery.

        This method processes inbound envelopes by:
        - Checking signature requirements for critical frames first
        - Handling KeyAnnounce frames through the key management handler
        - Decrypting envelopes and frames as needed
        - Verifying signatures
        - Applying security policies
        - Handling outbound security for LOCAL origin envelopes

        Returns:
            Processed envelope for continued delivery, or None to halt delivery
        """
        from naylence.fame.util.logging import getLogger

        logger = getLogger(__name__)

        # SECURITY ENFORCEMENT: Check signature requirements for critical frames
        # BEFORE frame-specific handling
        if context and context.origin_type != DeliveryOriginType.LOCAL and self._policy:
            # Critical frames must always be signed regardless of policy
            from naylence.fame.core.protocol.frames import (
                KeyAnnounceFrame,
                KeyRequestFrame,
                SecureAcceptFrame,
                SecureOpenFrame,
            )

            is_critical_frame = isinstance(
                envelope.frame,
                KeyRequestFrame | KeyAnnounceFrame | SecureOpenFrame | SecureAcceptFrame,
            )

            if is_critical_frame:
                is_signed = envelope.sec is not None and envelope.sec.sig is not None
                if not is_signed:
                    logger.error(
                        "critical_frame_unsigned_rejected",
                        envp_id=envelope.id,
                        frame_type=envelope.frame.type,
                        reason="critical_frames_must_be_signed",
                    )
                    return None  # Reject unsigned critical frames

            # For all other frames, check policy-based signature requirements
            elif self._policy.is_signature_required(envelope, context):
                is_signed = envelope.sec is not None and envelope.sec.sig is not None
                if not is_signed:
                    # Handle violation action for non-critical frames
                    violation_action = self._policy.get_unsigned_violation_action(envelope, context)
                    logger.warning(
                        "unsigned_envelope_violation",
                        envp_id=envelope.id,
                        frame_type=envelope.frame.type,
                        action=violation_action.name,
                    )

                    from naylence.fame.security.policy.security_policy import (
                        SecurityAction,
                    )

                    if violation_action in (SecurityAction.REJECT, SecurityAction.NACK):
                        return None  # Halt delivery

        # AUTHORIZATION: Check authorization for non-local envelopes
        if context and context.origin_type != DeliveryOriginType.LOCAL and self._authorizer:
            try:
                auth_result = await self._authorizer.authorize(node, envelope, context)
                if not auth_result:
                    logger.warning(
                        "envelope_authorization_failed",
                        envp_id=envelope.id,
                        frame_type=envelope.frame.type,
                        origin_type=(context.origin_type.name if context.origin_type else "unknown"),
                    )
                    return None  # Halt delivery for unauthorized envelope

                # Update the context with the authorization result if it changed
                if context.security:
                    context.security.authorization = auth_result
                else:
                    from naylence.fame.core.protocol.delivery_context import (
                        SecurityContext,
                    )

                    context.security = SecurityContext(authorization=auth_result)

                logger.debug(
                    "envelope_authorization_successful",
                    envp_id=envelope.id,
                    frame_type=envelope.frame.type,
                    principal=auth_result.principal if auth_result else None,
                )

            except Exception as e:
                logger.error(
                    "envelope_authorization_error",
                    envp_id=envelope.id,
                    frame_type=envelope.frame.type,
                    error=str(e),
                )
                return None  # Halt delivery on authorization error

        # Handle KeyAnnounce frames first
        if envelope.frame.type == "KeyAnnounce":
            if self._key_frame_handler:  # Check Sentinel's key frame handler first for correlation routing
                await self._key_frame_handler.accept_key_announce(envelope, context)
                return None
            elif self._key_management_handler:
                await self._key_management_handler.accept_key_announce(envelope, context)
                return None
            else:
                logger.debug("keyannounce_frame_ignored_no_key_handler", envp_id=envelope.id)
                return envelope  # No key handler, pass through

        # Handle KeyRequest frames for Sentinel nodes
        if envelope.frame.type == "KeyRequest":
            if self._key_frame_handler:
                handled_locally = await self._key_frame_handler.accept_key_request(envelope, context)
                if handled_locally:
                    return None  # Handled locally, no further processing needed
                else:
                    # Needs routing through pipeline, continue processing
                    pass
            elif self._key_manager:
                # Child nodes without routing can still handle KeyRequest frames directly
                await self._handle_child_key_request(envelope, context)
                return None  # Handled by key manager, no further processing needed
            else:
                logger.debug("keyrequest_frame_ignored_no_handler", envp_id=envelope.id)
                return envelope  # No key frame handler, pass through

        # Handle all other security processing (decryption, outbound security, signature verification)
        if self._envelope_security_handler:
            (
                processed_envelope,
                should_continue,
            ) = await self._envelope_security_handler.handle_envelope_security(envelope, context)

            if not should_continue:
                return None  # envelope was queued for missing keys –
                # do not continue with normal delivery logic
        else:
            # No security handler yet - pass through envelope as-is
            processed_envelope = envelope

        logger.debug("on_deliver_security_processing_complete", envp_id=processed_envelope.id)
        return processed_envelope

    async def on_routing_action_selected(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        selected: Any,  # RoutingAction
        state: Any,  # RouterState
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[Any]:  # RoutingAction | None
        """
        Route authorization hook - invoked after routing policy selects an action.

        This method provides centralized route authorization by:
        1. Mapping the RoutingAction to an authorization action token
        2. Calling authorizer.authorize_route() if available
        3. Returning a Deny action on authorization failure (opaque on wire)

        Args:
            node: The node performing the routing
            envelope: The envelope being routed
            selected: The RoutingAction selected by routing policy
            state: The current router state
            context: Optional delivery context

        Returns:
            The action to execute (selected if authorized, Deny if denied)
        """
        from naylence.fame.sentinel.router import (
            Deny,
            DenyOptions,
            map_routing_action_to_authorization_action,
        )

        # If no authorizer or authorizer doesn't implement authorize_route, allow
        if not self._authorizer:
            return selected

        if not callable(getattr(self._authorizer, "authorize_route", None)):
            return selected

        # Map RoutingAction to authorization action token
        action_token = map_routing_action_to_authorization_action(selected)

        # Terminal actions (Drop, Deny) don't need authorization
        if action_token is None:
            return selected

        try:
            auth_result = await self._authorizer.authorize_route(
                node,
                envelope,
                action_token,  # type: ignore[arg-type]  # action_token is guaranteed to be RuleAction by this point
                context,
            )

            # None means allow (authorizer has no opinion)
            if auth_result is None:
                return selected

            # Check authorization result
            if auth_result.authorized:
                logger.debug(
                    "route_authorization_allowed",
                    envp_id=envelope.id,
                    action=action_token,
                    frame_type=envelope.frame.type if envelope.frame else None,
                    matched_rule=auth_result.matched_rule,
                )
                return selected

            # Authorization denied - return Deny action with opaque NACK
            logger.warning(
                "route_authorization_denied_by_policy",
                envp_id=envelope.id,
                action=action_token,
                frame_type=envelope.frame.type if envelope.frame else None,
                origin_type=context.origin_type if context else None,
                to=str(envelope.to) if envelope.to else None,
                denial_reason=auth_result.denial_reason or "policy_denied",
                matched_rule=auth_result.matched_rule,
            )

            # Determine disclosure mode from configuration
            disclosure = self._get_nack_disclosure_mode()

            return Deny(
                DenyOptions(
                    internal_reason=auth_result.denial_reason or "unauthorized_route",
                    denied_action=action_token,
                    matched_rule=auth_result.matched_rule,
                    disclosure=disclosure,
                    context={
                        "frame_type": envelope.frame.type if envelope.frame else None,
                        "origin_type": str(context.origin_type) if context else None,
                    },
                )
            )
        except Exception as error:
            logger.error(
                "route_authorization_error",
                envp_id=envelope.id,
                action=action_token,
                error=str(error),
            )
            # On error, deny by default for security
            return Deny(
                DenyOptions(
                    internal_reason="authorization_error",
                    denied_action=action_token,
                    disclosure="opaque",
                )
            )

    def _get_nack_disclosure_mode(self) -> str:
        """Get the NACK disclosure mode from policy configuration."""
        # Default to opaque for security
        return "opaque"

    async def on_forward_upstream(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle security processing for upstream forwarding.

        This method processes outbound envelopes by:
        - Applying outbound security for LOCAL origin envelopes
        - Encrypting/signing as needed
        - Enforcing outbound security policies

        Returns:
            Processed envelope for continued forwarding, or None to halt forwarding
        """
        from naylence.fame.util.logging import getLogger

        logger = getLogger(__name__)

        logger.debug("on_forward_upstream_start", envp_id=envelope.id)

        # Handle outbound security for LOCAL origin envelopes
        if context and context.origin_type == DeliveryOriginType.LOCAL:
            if (
                self._envelope_security_handler
                and not await self._envelope_security_handler.handle_outbound_security(envelope, context)
            ):
                logger.debug("on_forward_upstream_queued_for_keys", envp_id=envelope.id)
                return None  # envelope was queued for missing keys – do not forward

        logger.debug("on_forward_upstream_security_processing_complete", envp_id=envelope.id)
        return envelope

    async def on_forward_to_route(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle security processing for forwarding to downstream routes.

        This method processes outbound envelopes for routing by:
        - Applying outbound security for LOCAL origin envelopes
        - Ensuring critical frames remain signed when forwarded
        - Encrypting/signing as needed for downstream transmission
        - Enforcing routing-specific security policies

        Returns:
            Processed envelope for continued forwarding, or None to halt forwarding
        """
        from naylence.fame.core import DeliveryOriginType
        from naylence.fame.util.logging import getLogger

        logger = getLogger(__name__)

        logger.debug("on_forward_to_route_start", envp_id=envelope.id, next_segment=next_segment)

        # CRITICAL FRAME FORWARDING: Ensure critical frames remain signed when forwarded
        if context and self._policy:
            from naylence.fame.core.protocol.frames import (
                KeyAnnounceFrame,
                KeyRequestFrame,
                SecureAcceptFrame,
                SecureOpenFrame,
            )

            is_critical_frame = isinstance(
                envelope.frame,
                KeyRequestFrame | KeyAnnounceFrame | SecureOpenFrame | SecureAcceptFrame,
            )

            if is_critical_frame:
                is_currently_signed = envelope.sec is not None and envelope.sec.sig is not None

                if not is_currently_signed:
                    # Critical frame must be signed before forwarding
                    if self._envelope_security_handler:
                        # Create a LOCAL context for outbound security processing
                        local_context = FameDeliveryContext(
                            origin_type=DeliveryOriginType.LOCAL,
                            from_system_id=node.id,
                        )
                        # Copy relevant metadata from original context
                        if context.meta:
                            local_context.meta = context.meta.copy()
                        if context.security:
                            local_context.security = context.security

                        # Apply outbound security (signing)
                        if not await self._envelope_security_handler.handle_outbound_security(
                            envelope, local_context
                        ):
                            logger.warning(
                                "critical_frame_forwarding_failed_missing_keys",
                                envp_id=envelope.id,
                                frame_type=envelope.frame.type,
                                next_segment=next_segment,
                            )
                            return None  # queued for missing keys
                    else:
                        logger.error(
                            "critical_frame_forwarding_failed_no_security_handler",
                            envp_id=envelope.id,
                            frame_type=envelope.frame.type,
                            next_segment=next_segment,
                        )
                        return None  # Cannot forward unsigned critical frame without security handler

        # Handle outbound security for LOCAL origin envelopes
        if context and context.origin_type == DeliveryOriginType.LOCAL:
            if (
                self._envelope_security_handler
                and not await self._envelope_security_handler.handle_outbound_security(envelope, context)
            ):
                logger.debug(
                    "on_forward_to_route_queued_for_keys",
                    envp_id=envelope.id,
                    next_segment=next_segment,
                )
                return None  # envelope was queued for missing keys – do not forward

        logger.debug(
            "on_forward_to_route_security_processing_complete",
            envp_id=envelope.id,
            next_segment=next_segment,
        )
        return envelope

    async def on_forward_to_peer(
        self,
        node: NodeLike,
        peer_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle security processing for forwarding to peers.

        This method processes outbound envelopes for peer forwarding by:
        - Applying outbound security for LOCAL origin envelopes
        - Ensuring critical frames remain signed when forwarded
        - Encrypting/signing as needed for peer transmission
        - Enforcing peer-specific security policies

        Returns:
            Processed envelope for continued forwarding, or None to halt forwarding
        """
        from naylence.fame.core import DeliveryOriginType
        from naylence.fame.util.logging import getLogger

        logger = getLogger(__name__)

        logger.debug("on_forward_to_peer_start", envp_id=envelope.id, peer_segment=peer_segment)

        # CRITICAL FRAME FORWARDING: Ensure critical frames remain signed when forwarded
        if context and self._policy:
            from naylence.fame.core.protocol.frames import (
                KeyAnnounceFrame,
                KeyRequestFrame,
                SecureAcceptFrame,
                SecureOpenFrame,
            )

            is_critical_frame = isinstance(
                envelope.frame,
                KeyRequestFrame | KeyAnnounceFrame | SecureOpenFrame | SecureAcceptFrame,
            )

            if is_critical_frame:
                is_currently_signed = envelope.sec is not None and envelope.sec.sig is not None

                if not is_currently_signed:
                    # Critical frame must be signed before forwarding
                    if self._envelope_security_handler:
                        # Create a LOCAL context for outbound security processing
                        local_context = FameDeliveryContext(
                            origin_type=DeliveryOriginType.LOCAL,
                            from_system_id=node.id,
                        )
                        # Copy relevant metadata from original context
                        if context.meta:
                            local_context.meta = context.meta.copy()
                        if context.security:
                            local_context.security = context.security

                        # Apply outbound security (signing)
                        if not await self._envelope_security_handler.handle_outbound_security(
                            envelope, local_context
                        ):
                            logger.warning(
                                "critical_frame_forwarding_failed_missing_keys",
                                envp_id=envelope.id,
                                frame_type=envelope.frame.type,
                                peer_segment=peer_segment,
                            )
                            return None  # queued for missing keys
                    else:
                        logger.error(
                            "critical_frame_forwarding_failed_no_security_handler",
                            envp_id=envelope.id,
                            frame_type=envelope.frame.type,
                            peer_segment=peer_segment,
                        )
                        return None  # Cannot forward unsigned critical frame without security handler

        # Handle outbound security for LOCAL origin envelopes
        if context and context.origin_type == DeliveryOriginType.LOCAL:
            if (
                self._envelope_security_handler
                and not await self._envelope_security_handler.handle_outbound_security(envelope, context)
            ):
                logger.debug(
                    "on_forward_to_peer_queued_for_keys",
                    envp_id=envelope.id,
                    peer_segment=peer_segment,
                )
                return None  # envelope was queued for missing keys – do not forward

        logger.debug(
            "on_forward_to_peer_security_processing_complete",
            envp_id=envelope.id,
            peer_segment=peer_segment,
        )
        return envelope

    async def on_forward_to_peers(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        peers: Any,
        exclude_peers: Any,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle security processing for forwarding to multiple peers.

        This method processes outbound envelopes for multi-peer forwarding by:
        - Applying outbound security for LOCAL origin envelopes
        - Encrypting/signing as needed for peer transmission
        - Enforcing broadcast-specific security policies

        Returns:
            Processed envelope for continued forwarding, or None to halt forwarding
        """
        from naylence.fame.core import DeliveryOriginType
        from naylence.fame.util.logging import getLogger

        logger = getLogger(__name__)

        logger.debug(
            "on_forward_to_peers_start",
            envp_id=envelope.id,
            peers=peers,
            exclude_peers=exclude_peers,
        )

        # CRITICAL FRAME FORWARDING: Ensure critical frames remain signed when forwarded
        if context and self._policy:
            from naylence.fame.core.protocol.frames import (
                KeyAnnounceFrame,
                KeyRequestFrame,
                SecureAcceptFrame,
                SecureOpenFrame,
            )

            is_critical_frame = isinstance(
                envelope.frame,
                KeyRequestFrame | KeyAnnounceFrame | SecureOpenFrame | SecureAcceptFrame,
            )

            if is_critical_frame:
                is_currently_signed = envelope.sec is not None and envelope.sec.sig is not None

                if not is_currently_signed:
                    # Critical frame must be signed before forwarding
                    if self._envelope_security_handler:
                        # Create a LOCAL context for outbound security processing
                        local_context = FameDeliveryContext(
                            origin_type=DeliveryOriginType.LOCAL,
                            from_system_id=node.id,
                        )
                        # Copy relevant metadata from original context
                        if context.meta:
                            local_context.meta = context.meta.copy()
                        if context.security:
                            local_context.security = context.security

                        # Apply outbound security (signing)
                        if not await self._envelope_security_handler.handle_outbound_security(
                            envelope, local_context
                        ):
                            logger.warning(
                                "critical_frame_forwarding_failed_missing_keys",
                                envp_id=envelope.id,
                                frame_type=envelope.frame.type,
                                peers=peers,
                            )
                            return None  # queued for missing keys
                    else:
                        logger.error(
                            "critical_frame_forwarding_failed_no_security_handler",
                            envp_id=envelope.id,
                            frame_type=envelope.frame.type,
                            peers=peers,
                        )
                        return None  # Cannot forward unsigned critical frame without security handler

        # Handle outbound security for LOCAL origin envelopes
        if context and context.origin_type == DeliveryOriginType.LOCAL:
            if (
                self._envelope_security_handler
                and not await self._envelope_security_handler.handle_outbound_security(envelope, context)
            ):
                logger.debug("on_forward_to_peers_queued_for_keys", envp_id=envelope.id)
                return None  # envelope was queued for missing keys – do not forward

        logger.debug("on_forward_to_peers_security_processing_complete", envp_id=envelope.id)
        return envelope

    async def on_epoch_change(self, node: NodeLike, epoch: str) -> None:
        """
        Handle epoch change events for the node.

        This method handles key management functionality when epochs change:
        - Announces keys to upstream if a key manager is available
        - Logs appropriate debug information

        Args:
            node: The node that received the epoch change
            epoch: The new epoch identifier
        """
        logger.debug("handle_epoch_change_security", epoch=epoch)

        if self._key_manager is not None:
            await self._key_manager.announce_keys_to_upstream()
        else:
            logger.debug("skipping_key_announcement_no_key_manager")

    async def on_node_stopped(self, node: NodeLike) -> None:
        """
        Handle node shutdown for all security components.

        This method implements the NodeEventListener interface and gracefully
        shuts down all security-related components including the key management
        handler.

        Args:
            node: The node that is being stopped
        """
        logger.debug("stopping_security_components", node_id=node.id)

        # Stop the key frame handler if it exists
        if self._key_frame_handler is not None:
            await self._key_frame_handler.stop()
            logger.debug("key_frame_handler_stopped")

        # Stop the key management handler if it exists
        if self._key_management_handler is not None:
            await self._key_management_handler.stop()
            logger.debug("key_management_handler_stopped")

        # Stop the key manager if present
        if self._key_manager is not None:
            await self._key_manager.on_node_stopped(node)
            logger.debug("key_manager_stopped")

        # Stop certificate manager if present and implements NodeEventListener
        if self._certificate_manager and isinstance(self._certificate_manager, NodeEventListener):
            await self._certificate_manager.on_node_stopped(node)
            logger.debug("certificate_manager_stopped")

        # Stop encryption manager if present and implements NodeEventListener
        if self._encryption and isinstance(self._encryption, NodeEventListener):
            await self._encryption.on_node_stopped(node)
            logger.debug("encryption_manager_stopped")

    async def _send_nack(
        self,
        node: NodeLike,
        original_env: FameEnvelope,
        reason: str = "security_policy_violation",
    ) -> None:
        """Send a negative-ack response for the given envelope."""
        from naylence.fame.core import (
            CreditUpdateFrame,
            DeliveryAckFrame,
            NodeHeartbeatFrame,
        )

        assert not isinstance(original_env.frame, CreditUpdateFrame)
        assert not isinstance(original_env.frame, NodeHeartbeatFrame), (
            "Cannot send NACK for system heartbeat frames"
        )
        dest = original_env.reply_to
        if not dest:
            from naylence.fame.util.logging import getLogger

            logger = getLogger(__name__)
            logger.debug("nack_no_destination", envp_id=original_env.id)
            return

        nack_frame = DeliveryAckFrame(ok=False, ref_id=original_env.id, code=reason)
        nack_env = node.envelope_factory.create_envelope(
            trace_id=original_env.trace_id,
            frame=nack_frame,
            to=dest,
            corr_id=original_env.corr_id,
        )

        ctx = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id=node.id)
        await node.deliver(nack_env, ctx)

    def _get_key_announce_handler(self):
        """Get the key announce handler from the key management handler."""
        if self._key_management_handler:
            return self._key_management_handler.accept_key_announce
        else:
            # Return a no-op function if no key management handler is available
            async def no_op_handler(envelope, context):
                pass

            return no_op_handler

    def get_encryption_key_id(self) -> Optional[str]:
        """Get the encryption key ID from the crypto provider.

        Returns the key ID of the node's encryption key, following the convention
        that encryption keys have "-enc" suffix and are marked with use="enc".
        """
        try:
            from naylence.fame.security.crypto.providers.crypto_provider import (
                get_crypto_provider,
            )

            crypto_provider = get_crypto_provider()
            return crypto_provider.encryption_key_id
        except Exception:
            return None

    async def on_welcome(self, welcome_frame: Any) -> None:
        """
        Handle certificate provisioning when a child node receives a welcome frame.

        This method encapsulates certificate provisioning logic that was previously
        scattered in UpstreamSessionManager. It handles the certificate provisioning
        based on the security policy and logs appropriate messages.

        Args:
            welcome_frame: The NodeWelcomeFrame received during admission
        """
        # If no certificate manager is available, nothing to do
        if not self._certificate_manager:
            return

        try:
            # Request certificate from CA service if needed (policy-driven)
            await self._certificate_manager.on_welcome(welcome_frame=welcome_frame)

            # if not cert_success:
            #     logger.warning(
            #         "certificate_provisioning_failed_proceeding_without_cert",
            #         node_id=welcome_frame.system_id,
            #         assigned_path=welcome_frame.assigned_path
            #     )
            #     # Continue without certificate - this maintains backward compatibility

        except RuntimeError as e:
            # Certificate validation failures are security-critical and should not be ignored
            # Re-raise the exception to prevent the child node from proceeding
            if "certificate validation failed" in str(e):
                logger.error(
                    "child_node_certificate_validation_failed_stopping_node",
                    error=str(e),
                    node_id=getattr(welcome_frame, "system_id", None),
                    assigned_path=getattr(welcome_frame, "assigned_path", None),
                    message="Child node cannot proceed due to certificate validation failure",
                )
                raise  # Re-raise to prevent child node from continuing
            else:
                # Non-certificate validation RuntimeErrors can be handled with backward compatibility
                logger.warning(
                    "certificate_provisioning_error_proceeding_without_cert",
                    error=str(e),
                    node_id=getattr(welcome_frame, "system_id", None),
                    assigned_path=getattr(welcome_frame, "assigned_path", None),
                    exc_info=True,
                )
        except Exception as e:
            # Other exceptions (network errors, etc.) can be handled with backward compatibility
            logger.warning(
                "certificate_provisioning_error_proceeding_without_cert",
                error=str(e),
                node_id=getattr(welcome_frame, "system_id", None),
                assigned_path=getattr(welcome_frame, "assigned_path", None),
                exc_info=True,
            )
            # Continue without certificate on non-critical errors - this maintains backward compatibility

    async def on_heartbeat_received(self, envelope: FameEnvelope) -> None:
        """
        Handle heartbeat envelope verification based on security policy.

        This method encapsulates heartbeat verification logic that was previously
        handled directly in UpstreamSessionManager. It verifies envelope signatures
        if required by the security policy and logs appropriate messages.

        Args:
            envelope: The heartbeat envelope to verify
        """
        # If the envelope has a signature, verify it based on policy
        if envelope.sec and envelope.sec.sig:
            # Check if verification is required by policy
            if self._envelope_verifier:
                try:
                    await self._envelope_verifier.verify_envelope(envelope)
                    logger.debug("heartbeat_ack_envelope_verified")
                except Exception as e:
                    logger.warning(
                        "heartbeat_envelope_verification_failed",
                        envelope_id=getattr(envelope, "id", None),
                        error=str(e),
                        exc_info=True,
                    )
                    # Continue processing even if verification fails (backward compatibility)
            else:
                # No verifier available but signature present - check policy requirements
                try:
                    requirements = (
                        getattr(self._policy, "_requirements", None) or self._policy.requirements()
                    )
                    if requirements and requirements.verification_required:
                        logger.warning(
                            "heartbeat_signature_present_but_no_verifier_policy_requires_verification",
                            envelope_id=getattr(envelope, "id", None),
                        )
                        # Continue anyway for backward compatibility
                except Exception:
                    # If we can't determine policy requirements, log and continue
                    logger.debug(
                        "could_not_determine_verification_policy_allowing_heartbeat",
                        envelope_id=getattr(envelope, "id", None),
                    )

    async def on_child_attach(
        self,
        *,
        child_system_id: str,
        child_keys: Any,
        node_like: NodeLike,
        origin_type: Any = None,
        assigned_path: Optional[str] = None,
        old_assigned_path: Optional[str] = None,
        is_rebind: bool = False,
    ) -> None:
        """Handle child attachment security validation and key management."""
        from naylence.fame.errors.errors import FameTransportClose
        from naylence.fame.util.envelope_context import current_trace_id

        # Get our keys for validation
        our_keys = self._get_keys_to_provide()

        # Handle key removal for rebinds
        if is_rebind and old_assigned_path and self._key_manager:
            try:
                removed_count = await self._key_manager.remove_keys_for_path(old_assigned_path)
                logger.debug(
                    "removed_stale_keys_on_rebind",
                    system_id=child_system_id,
                    old_path=old_assigned_path,
                    removed_count=removed_count,
                )
            except Exception as e:
                logger.warning(
                    "failed_to_remove_stale_keys_on_rebind",
                    system_id=child_system_id,
                    old_path=old_assigned_path,
                    error=str(e),
                )

        sentinel_security_policy = node_like.security_manager.policy if node_like.security_manager else None
        if sentinel_security_policy:
            # Validate that the child provided keys meet our requirements for accepting them
            if child_keys:
                is_valid, reason = sentinel_security_policy.validate_attach_security_compatibility(
                    peer_keys=child_keys,  # Keys provided by the child
                    peer_requirements=None,  # We don't know child's requirements yet
                    node_like=node_like,
                )

                if not is_valid:
                    logger.warning(
                        "attach_child_security_validation_failed",
                        reason=reason,
                        child_system_id=child_system_id,
                        child_keys_count=len(child_keys),
                    )
                    # Note: We log warnings but don't fail the attach for backward compatibility
                    # In a stricter implementation, we might want to fail here
                else:
                    logger.debug(
                        "attach_child_security_validation_passed",
                        child_system_id=child_system_id,
                        child_keys_count=len(child_keys),
                    )

            # Validate that our keys meet what we should be providing
            is_valid, reason = sentinel_security_policy.validate_attach_security_compatibility(
                peer_keys=our_keys,  # Keys we're providing to the child
                peer_requirements=None,  # We don't know child's requirements yet
                node_like=node_like,
            )

            if not is_valid:
                logger.warning(
                    "attach_our_security_validation_warning",
                    reason=reason,
                    child_system_id=child_system_id,
                    our_keys_count=len(our_keys) if our_keys else 0,
                )
                # Note: We log warnings but don't fail the attach for backward compatibility
            else:
                logger.debug(
                    "attach_our_security_validation_passed",
                    child_system_id=child_system_id,
                    our_keys_count=len(our_keys) if our_keys else 0,
                )

        # Check if we're providing the right types of keys based on our policy
        if sentinel_security_policy:
            requirements = sentinel_security_policy.requirements()
            if our_keys:
                has_signing_key = any(
                    key.get("use") in ["sig", None]
                    and key.get("kty") == "OKP"
                    and key.get("crv") == "Ed25519"
                    for key in our_keys
                )
                has_encryption_key = any(
                    key.get("use") in ["enc", None]
                    and key.get("kty") == "OKP"
                    and key.get("crv") == "X25519"
                    for key in our_keys
                )

                # Log what we're providing vs what our policy suggests we should provide
                if requirements.require_signing_key_exchange and not has_signing_key:
                    logger.warning(
                        "attach_missing_signing_key",
                        child_system_id=child_system_id,
                        reason="Our policy requires signing but we're not providing signing keys",
                    )

                if requirements.require_encryption_key_exchange and not has_encryption_key:
                    logger.warning(
                        "attach_missing_encryption_key",
                        child_system_id=child_system_id,
                        reason="Our policy requires encryption but we're not providing encryption keys",
                    )
            elif requirements.require_signing_key_exchange or requirements.require_encryption_key_exchange:
                logger.warning(
                    "attach_no_keys_provided",
                    child_system_id=child_system_id,
                    require_signing=requirements.require_signing_key_exchange,
                    require_encryption=requirements.require_encryption_key_exchange,
                )

        # Add child keys to key manager if provided
        if child_keys and self._key_manager and assigned_path and origin_type:
            try:
                await self._key_manager.add_keys(
                    keys=child_keys,
                    physical_path=assigned_path,
                    origin=origin_type,
                    system_id=child_system_id,
                )
                logger.debug(
                    "added_child_attach_keys",
                    child_system_id=child_system_id,
                    assigned_path=assigned_path,
                    keys_count=len(child_keys),
                )
            except FameTransportClose:  # pragma: no cover – defensive
                logger.error(
                    "failed_to_add_attach_keys_will_retry_on_epoch_change",
                    parent_id=child_system_id,
                    trace_id=current_trace_id(),
                    exc_info=True,
                )
            except Exception as e:
                logger.error(
                    "failed_to_add_attach_keys",
                    child_system_id=child_system_id,
                    assigned_path=assigned_path,
                    error=str(e),
                    exc_info=True,
                )

    def get_shareable_keys(self) -> Any:
        """Get keys to provide to child nodes, respecting security manager configuration."""
        # Check if the security manager doesn't provide envelope signing (no crypto), don't provide keys
        if self.envelope_signer is None:
            logger.debug("no_keys_provided_no_crypto_components")
            return None

        # Use crypto provider to get keys
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        crypto_provider = get_crypto_provider()
        if not crypto_provider:
            return None

        keys = []

        # Try to get certificate-enabled signing JWK
        node_jwk = crypto_provider.node_jwk()
        if node_jwk:
            keys.append(node_jwk)

        # Always get all keys from JWKS (includes encryption keys and fallback signing key)
        jwks = crypto_provider.get_jwks()
        if jwks and jwks.get("keys"):
            for jwk in jwks["keys"]:
                # If we already have a certificate-enabled signing key, skip the regular signing key
                if node_jwk and jwk.get("kid") == node_jwk.get("kid") and jwk.get("use") != "enc":
                    continue
                keys.append(jwk)

        return keys if keys else None

    def _get_keys_to_provide(self) -> Any:
        """Internal method that delegates to get_shareable_keys."""
        return self.get_shareable_keys()

    async def _handle_child_key_request(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ) -> None:
        """
        Handle KeyRequest frames for Child nodes that don't have routing capabilities.

        This is a simplified version of the KeyFrameHandler logic for nodes that only
        need to respond to key requests without routing or forwarding capabilities.
        """
        from naylence.fame.core.protocol.frames import KeyRequestFrame

        assert isinstance(envelope.frame, KeyRequestFrame)
        assert context and context.origin_type
        assert self._key_manager, "KeyManager must be set for KeyRequest handling"

        frame: KeyRequestFrame = envelope.frame

        origin_sid = context.from_system_id if context.from_system_id else None
        if not origin_sid:
            logger.warning("missing_origin_sid_for_key_request", envp_id=envelope.id)
            return

        logger.debug(
            "handling_key_request_for_child_node",
            address=frame.address,
            kid=frame.kid,
            corr_id=envelope.corr_id,
            origin_sid=origin_sid,
        )

        # Handle key requests by key ID or address
        if frame.kid:
            # Direct key ID request
            await self._key_manager.handle_key_request(
                kid=frame.kid,
                from_seg=origin_sid,
                physical_path=frame.physical_path,
                origin=context.origin_type,
                corr_id=envelope.corr_id,
                original_client_sid=envelope.sid,  # Pass original client SID for stickiness
            )
        elif frame.address:
            # Address-based request - Child node should check if this logical address
            # matches any of its local bindings
            # Ignore the physical_path from the request as it's likely the originator's path, not ours

            address_str = str(frame.address)
            logger.debug(
                "child_node_checking_address_match",
                requested_address=address_str,
                envp_id=envelope.id,
            )

            # For Child nodes, we should provide our own keys when the logical address matches our bindings
            # Try to get the encryption key ID from our crypto provider first
            try:
                from naylence.fame.security.crypto.providers.crypto_provider import (
                    get_crypto_provider,
                )

                crypto_provider = get_crypto_provider()
                if crypto_provider and crypto_provider.encryption_key_id:
                    encryption_key_id = crypto_provider.encryption_key_id
                    if encryption_key_id:
                        logger.debug(
                            "child_node_responding_with_own_encryption_key_id",
                            key_id=encryption_key_id,
                            requested_address=address_str,
                            envp_id=envelope.id,
                        )
                        await self._key_manager.handle_key_request(
                            kid=encryption_key_id,
                            from_seg=origin_sid,
                            physical_path=None,  # Let key manager determine the correct path
                            origin=context.origin_type,
                            corr_id=envelope.corr_id,
                            original_client_sid=envelope.sid,  # Pass original client SID for stickiness
                        )

                        return

                # If no encryption key, try signature key as fallback
                if crypto_provider and crypto_provider.signature_key_id:
                    signature_key_id = crypto_provider.signature_key_id
                    if signature_key_id:
                        logger.debug(
                            "child_node_responding_with_own_signature_key_id",
                            key_id=signature_key_id,
                            requested_address=address_str,
                            envp_id=envelope.id,
                        )
                        await self._key_manager.handle_key_request(
                            kid=signature_key_id,
                            from_seg=origin_sid,
                            physical_path=None,  # Let key manager determine the correct path
                            origin=context.origin_type,
                            corr_id=envelope.corr_id,
                            original_client_sid=envelope.sid,  # Pass original client SID for stickiness
                        )
                        return

            except (ImportError, AttributeError, ValueError) as e:
                logger.debug(
                    "crypto_provider_key_lookup_failed",
                    error=str(e),
                    envp_id=envelope.id,
                )

            # If we couldn't get keys from crypto provider, log and ignore the request
            logger.debug(
                "child_node_cannot_resolve_address_key_request",
                address=frame.address,
                reason="no_crypto_provider_keys_found",
                envp_id=envelope.id,
            )
        else:
            logger.warning("key_request_missing_both_kid_and_address", envp_id=envelope.id)
