import asyncio
from time import monotonic
from typing import Optional

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyAnnounceFrame,
    KeyRequestFrame,
    generate_id,
    local_delivery_context,
)
from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator, KeyValidationError
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.util import logging
from naylence.fame.util.envelope_context import current_trace_id
from naylence.fame.util.task_spawner import TaskSpawner

logger = logging.getLogger(__name__)


KEY_REQUEST_TIMEOUT_SEC = 5  # 1st wait (as before)
KEY_REQUEST_RETRIES = 3  # how many times we re-ask the parent
KEY_GC_INTERVAL_SEC = 10  # how often the janitor runs


class KeyManagementHandler(TaskSpawner):
    def __init__(
        self,
        node_like: NodeLike,
        key_manager: Optional[KeyManager],
        key_validator: AttachmentKeyValidator,
        encryption_manager=None,
    ):
        TaskSpawner.__init__(self)
        self._node = node_like
        self._key_manager = key_manager
        self._key_validator = key_validator
        self._encryption_manager = encryption_manager
        self._pending_key_requests: dict[
            str, tuple[asyncio.Future[None], DeliveryOriginType, str, float, int]
        ] = {}

        self._pending_envelopes: dict[str, list[tuple[FameEnvelope, FameDeliveryContext]]] = {}

        # Separate queue for envelopes waiting for encryption keys
        self._pending_encryption_envelopes: dict[str, list[tuple[FameEnvelope, FameDeliveryContext]]] = {}
        self._pending_encryption_key_requests: dict[
            str, tuple[asyncio.Future[None], DeliveryOriginType, str, float, int]
        ] = {}

        # Mapping from correlation IDs to address requests (for address-based key requests)
        self._correlation_to_address: dict[str, str] = {}

        self._is_started = False

    async def start(self):
        self._is_started = True
        self.spawn(self._gc_key_requests(), name="key-request-gc")
        # Add own public keys to key manager for key lookups
        await self._register_own_public_keys()

    async def stop(self):
        """Stop the key management handler and cancel background tasks."""
        self._is_started = False

        # Give the _gc_key_requests task a moment to see the flag and exit gracefully
        await asyncio.sleep(0.1)

        # Shutdown any remaining spawned tasks
        await self.shutdown_tasks(grace_period=0.01, cancel_hang=True, join_timeout=1.0)

    async def accept_key_announce(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming KeyAnnounce frames."""
        frame = envelope.frame
        assert isinstance(frame, KeyAnnounceFrame)
        assert envelope.sid
        assert context
        assert context.origin_type

        # Skip key management if no key manager is available
        if self._key_manager is None:
            logger.debug("skipping_key_announce_no_key_manager", envelope_id=envelope.id)
            return

        origin_system_id = self._get_source_system_id(context)
        assert origin_system_id

        # For on-demand key requests, perform certificate pre-validation with warning behavior
        validated_keys = []
        if frame.keys:
            # Validate each key, skip invalid certificates with warnings
            for key in frame.keys:
                try:
                    await self._key_validator.validate_key(key)
                    validated_keys.append(key)
                except KeyValidationError as e:
                    logger.warning(
                        "skipping_key_due_to_certificate_validation_failure",
                        kid=key.get("kid", "unknown"),
                        from_system_id=origin_system_id,
                        from_physical_path=frame.physical_path,
                        error=str(e),
                        scenario="on_demand_key_request",
                        action="skipped_key_not_added_to_store",
                    )

        # Only proceed with keys that passed validation
        if validated_keys:
            # Check if this is a correlation-routed KeyAnnounce (SID validation should be skipped)
            is_correlation_routed = bool(envelope.corr_id)

            await self._key_manager.add_keys(
                keys=validated_keys,
                sid=envelope.sid,
                physical_path=frame.physical_path,
                system_id=origin_system_id,
                origin=context.origin_type,
                skip_sid_validation=is_correlation_routed,  # Skip SID validation for correlation routing
            )

            # Handle key-ID-based requests (traditional approach)
            for jwk in validated_keys:
                self._on_new_key(jwk["kid"])

            # Handle address-based requests using correlation ID
            if envelope.corr_id and envelope.corr_id in self._correlation_to_address:
                # This is a response to an address-based request
                original_address = self._correlation_to_address.pop(envelope.corr_id)
                logger.debug(
                    "received_key_announce_for_address_request",
                    corr_id=envelope.corr_id,
                    original_address=original_address,
                    key_count=len(validated_keys),
                )

                # Also add keys under the target address for future lookups
                if self._key_manager is not None:
                    await self._key_manager.add_keys(
                        keys=validated_keys,
                        sid=envelope.sid,
                        physical_path=original_address,  # Use target address as path for indexing
                        system_id=origin_system_id,
                        origin=context.origin_type,
                        skip_sid_validation=True,  # Skip SID validation for correlation routing
                    )
                    logger.debug(
                        "added_keys_for_target_address",
                        target_address=original_address,
                        key_count=len(validated_keys),
                    )

                # Resolve pending request and replay queued envelopes
                self._on_new_key_for_address_by_correlation(original_address, validated_keys)
        else:
            logger.warning(
                "no_valid_keys_remaining_after_certificate_validation",
                from_system_id=origin_system_id,
                from_physical_path=frame.physical_path,
                total_keys=len(frame.keys) if frame.keys else 0,
                scenario="on_demand_key_request",
            )

        # Handle address-based requests (when KeyAnnounce includes address)
        if hasattr(frame, "address") and frame.address:
            self._on_new_key_for_address(frame.address, validated_keys if validated_keys else frame.keys)

    def _get_source_system_id(self, context: Optional[FameDeliveryContext]):
        """Extract source system ID from delivery context."""
        source_system_id = None
        if context and context.from_system_id:
            source_system_id = context.from_system_id
        return source_system_id

    async def _maybe_request_encryption_key(
        self, kid: str, origin: DeliveryOriginType, from_system_id: str
    ) -> None:
        if kid in self._pending_encryption_key_requests or not self._node.has_parent:
            return

        logger.debug(
            "requesting_encryption_key_from_parent",
            kid=kid,
            trace_id=current_trace_id(),
        )
        fut = asyncio.Future()
        self._pending_encryption_key_requests[kid] = (
            fut,
            origin,
            from_system_id,
            monotonic() + KEY_REQUEST_TIMEOUT_SEC,
            0,
        )

        req = self._node.envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=KeyRequestFrame(kid=kid, physical_path=self._node.physical_path),
            corr_id=generate_id(),
        )

        logger.debug("sending_enc_key_request", kid=kid)

        assert origin == DeliveryOriginType.LOCAL  # encryption requests come from local processing
        # Forward to parent to get the key
        self.spawn(
            self._node.forward_upstream(req, context=local_delivery_context(self._node.id)),
            name=f"send-enc-keyreq-{kid}",
        )

    async def _maybe_request_encryption_key_by_address(
        self, address: "FameAddress", origin: DeliveryOriginType, from_system_id: str
    ) -> None:
        """Request an encryption key for a specific address.

        This method sends a KeyRequest with the address field set, allowing
        the upstream system to resolve the address to the appropriate encryption key.
        This works for both logical and physical addresses.
        """
        address_key = str(address)

        if address_key in self._pending_encryption_key_requests or not self._node.has_parent:
            return

        logger.debug(
            "requesting_encryption_key_from_parent_by_address",
            address=address_key,
            trace_id=current_trace_id(),
        )
        fut = asyncio.Future()
        self._pending_encryption_key_requests[address_key] = (
            fut,
            origin,
            from_system_id,
            monotonic() + KEY_REQUEST_TIMEOUT_SEC,
            0,
        )

        # Create KeyRequest with address field instead of kid
        corr_id = generate_id()
        req = self._node.envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=KeyRequestFrame(
                address=address,  # Request by address
                physical_path=self._node.physical_path,
            ),
            corr_id=corr_id,
        )

        logger.debug("sending_enc_key_request", by_address=address)

        # Store correlation ID mapping for address-based requests
        self._correlation_to_address[corr_id] = address_key

        assert origin == DeliveryOriginType.LOCAL  # encryption requests come from local processing
        # Forward to parent to get the key
        self.spawn(
            self._node.forward_upstream(req, context=local_delivery_context(self._node.id)),
            name=f"send-enc-keyreq-addr-{address_key}",
        )

    async def _maybe_request_signing_key(
        self, kid: str, origin: DeliveryOriginType, from_system_id: str
    ) -> None:
        if kid in self._pending_key_requests or not self._node.has_parent:
            return

        # Check if physical path is available - if not, skip key request during attachment
        try:
            physical_path = self._node.physical_path
        except RuntimeError:
            logger.debug(
                "skipping_key_request_during_attachment",
                kid=kid,
                reason="physical_path_not_yet_available",
                trace_id=current_trace_id(),
            )
            return  # Skip key request during attachment - will be retried later

        logger.debug("requesting_key_from_parent", kid=kid, trace_id=current_trace_id())

        fut = asyncio.Future()

        self._pending_key_requests[kid] = (
            fut,
            origin,
            from_system_id,
            monotonic() + KEY_REQUEST_TIMEOUT_SEC,
            0,
        )

        envelope = self._node.envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=KeyRequestFrame(kid=kid, physical_path=physical_path),
            corr_id=generate_id(),
        )

        logger.debug("sending_signing_key_request", kid=kid)

        if origin == DeliveryOriginType.UPSTREAM:
            self.spawn(
                self._node.forward_upstream(envelope, context=local_delivery_context(self._node.id)),
                name=f"send-keyreq-upstream-{kid}",
            )
        elif origin == DeliveryOriginType.PEER:
            from naylence.fame.node.routing_node_like import RoutingNodeLike

            if not isinstance(self._node, RoutingNodeLike):
                raise RuntimeError("Key requests to peers are only supported in routing nodes")
            self.spawn(
                self._node.forward_to_peer(
                    from_system_id,
                    envelope,
                    context=local_delivery_context(self._node.id),
                ),
                name=f"send-keyreq-peer-{kid}",
            )

    def _on_new_key(self, kid: str) -> None:
        # Handle signing key requests
        entry = self._pending_key_requests.pop(kid, None)
        if entry:
            fut, *_ = entry
            if not fut.done():
                fut.set_result(None)

        # Handle encryption key requests
        enc_entry = self._pending_encryption_key_requests.pop(kid, None)
        if enc_entry:
            fut, *_ = enc_entry
            if not fut.done():
                fut.set_result(None)

        # Notify encryption manager that key is available (if it has the notify method)
        if self._encryption_manager and hasattr(self._encryption_manager, "notify_key_available"):
            self.spawn(
                self._encryption_manager.notify_key_available(kid),
                name=f"notify-encryption-manager-{kid}",
            )

        # Replay envelopes waiting for signing keys
        for env, ctx in self._pending_envelopes.pop(kid, []):
            self.spawn(self._node.deliver(env, ctx), name=f"replay-after-signing-key-{kid}")

        # Replay envelopes waiting for encryption keys
        for env, ctx in self._pending_encryption_envelopes.pop(kid, []):
            self.spawn(self._node.deliver(env, ctx), name=f"replay-after-encryption-key-{kid}")

    def _on_new_key_for_address(self, address: FameAddress, keys: list[dict]) -> None:
        """Handle key arrival for address-based requests."""
        address_key = str(address)

        logger.debug(
            "processing_key_announce_for_address",
            address=address_key,
            key_count=len(keys),
            keys=[k.get("kid", "unknown") for k in keys],
        )

        # Notify encryption manager for all keys that were added
        if self._encryption_manager and hasattr(self._encryption_manager, "notify_key_available"):
            for key in keys:
                kid = key.get("kid")
                if kid:
                    # Notify about the actual key ID
                    self.spawn(
                        self._encryption_manager.notify_key_available(kid),
                        name=f"notify-encryption-manager-{kid}",
                    )
                    # Also notify about the address-based temporary key ID
                    # This allows envelopes queued under "request-{address}" to be processed
                    address_based_key_id = f"request-{address_key}"
                    self.spawn(
                        self._encryption_manager.notify_key_available(address_based_key_id),
                        name=f"notify-encryption-manager-{address_based_key_id}",
                    )

        # Handle encryption key requests for this address
        enc_entry = self._pending_encryption_key_requests.pop(address_key, None)
        if enc_entry:
            fut, *_ = enc_entry
            if not fut.done():
                fut.set_result(None)
            logger.debug("resolved_pending_encryption_request_for_address", address=address_key)

        # Replay envelopes waiting for encryption keys for this address
        pending_envelopes = self._pending_encryption_envelopes.pop(address_key, [])
        if pending_envelopes:
            logger.debug(
                "replaying_envelopes_for_address",
                address=address_key,
                envelope_count=len(pending_envelopes),
            )
            for env, ctx in pending_envelopes:
                self.spawn(
                    self._node.deliver(env, ctx),
                    name=f"replay-after-address-key-{address_key}",
                )

    def _on_new_key_for_address_by_correlation(self, address_key: str, keys: list[dict]) -> None:
        """Handle key arrival for address-based requests identified by correlation ID."""
        logger.debug(
            "processing_key_announce_for_address_by_correlation",
            address_key=address_key,
            key_count=len(keys),
            keys=[k.get("kid", "unknown") for k in keys],
        )

        # Notify encryption manager for all keys that were added
        if self._encryption_manager and hasattr(self._encryption_manager, "notify_key_available"):
            for key in keys:
                kid = key.get("kid")
                if kid:
                    # Notify about the actual key ID
                    self.spawn(
                        self._encryption_manager.notify_key_available(kid),
                        name=f"notify-encryption-manager-{kid}",
                    )
                    # Also notify about the address-based temporary key ID
                    # This allows envelopes queued under "request-{address}" to be processed
                    address_based_key_id = f"request-{address_key}"
                    self.spawn(
                        self._encryption_manager.notify_key_available(address_based_key_id),
                        name=f"notify-encryption-manager-{address_based_key_id}",
                    )

        # Handle encryption key requests for this address
        enc_entry = self._pending_encryption_key_requests.pop(address_key, None)
        if enc_entry:
            fut, *_ = enc_entry
            if not fut.done():
                fut.set_result(None)
            logger.debug(
                "resolved_pending_encryption_request_for_address_by_correlation",
                address_key=address_key,
            )

        # Replay envelopes waiting for encryption keys for this address
        pending_envelopes = self._pending_encryption_envelopes.pop(address_key, [])
        if pending_envelopes:
            logger.debug(
                "replaying_envelopes_for_address_by_correlation",
                address_key=address_key,
                envelope_count=len(pending_envelopes),
            )
            for env, ctx in pending_envelopes:
                self.spawn(
                    self._node.deliver(env, ctx),
                    name=f"replay-after-address-key-{address_key}",
                )

    async def _gc_key_requests(self):
        """
        Background task:
        • Retries or times-out pending key fetches (both signing and encryption).
        • Flushes/drops queued envelopes when we give up.
        """
        from time import monotonic

        try:
            while self._is_started:
                await asyncio.sleep(KEY_GC_INTERVAL_SEC)
                now = monotonic()

                # Handle signing key requests
                for kid, (fut, origin, from_system_id, expires, retries) in list(
                    self._pending_key_requests.items()
                ):
                    if fut.done():  # already resolved ⇒ clean
                        self._pending_key_requests.pop(kid, None)
                        continue

                    if now < expires:  # still within TTL
                        continue

                    if retries + 1 < KEY_REQUEST_RETRIES:  # ➜ retry
                        logger.warning("signing_key_request_retry", kid=kid, attempt=retries + 2)
                        self._pending_key_requests[kid] = (
                            fut,
                            origin,
                            from_system_id,
                            now + KEY_REQUEST_TIMEOUT_SEC,
                            retries + 1,
                        )
                        await self._maybe_request_signing_key(
                            kid, origin, from_system_id
                        )  # fire another request
                    else:  # ➜ give up
                        logger.error("signing_key_request_failed", kid=kid)
                        fut.set_exception(asyncio.TimeoutError("Signing key fetch failed"))

                        # drop / NACK queued envelopes
                        for env, ctx in self._pending_envelopes.pop(kid, []):
                            logger.error(
                                "dropping_envelope_missing_signing_key",
                                kid=kid,
                                envp_id=env.id,
                            )
                        self._pending_key_requests.pop(kid, None)

                # Handle encryption key requests
                for kid, (fut, origin, from_system_id, expires, retries) in list(
                    self._pending_encryption_key_requests.items()
                ):
                    if fut.done():  # already resolved ⇒ clean
                        self._pending_encryption_key_requests.pop(kid, None)
                        continue

                    if now < expires:  # still within TTL
                        continue

                    if retries + 1 < KEY_REQUEST_RETRIES:  # ➜ retry
                        logger.warning("encryption_key_request_retry", kid=kid, attempt=retries + 2)
                        self._pending_encryption_key_requests[kid] = (
                            fut,
                            origin,
                            from_system_id,
                            now + KEY_REQUEST_TIMEOUT_SEC,
                            retries + 1,
                        )
                        await self._maybe_request_encryption_key(
                            kid, origin, from_system_id
                        )  # fire another request
                    else:  # ➜ give up
                        logger.error("encryption_key_request_failed", kid=kid)
                        fut.set_exception(asyncio.TimeoutError("Encryption key fetch failed"))

                        # drop / NACK queued envelopes
                        for env, ctx in self._pending_encryption_envelopes.pop(kid, []):
                            logger.error(
                                "dropping_envelope_missing_encryption_key",
                                kid=kid,
                                envp_id=env.id,
                            )
                        self._pending_encryption_key_requests.pop(kid, None)

                        # Clean up correlation mapping if this was an address-based request
                        corr_ids_to_remove = [
                            corr_id
                            for corr_id, addr_key in self._correlation_to_address.items()
                            if addr_key == kid
                        ]
                        for corr_id in corr_ids_to_remove:
                            self._correlation_to_address.pop(corr_id, None)

        except asyncio.CancelledError:
            logger.debug("key_request_gc_cancelled")
            # Clean up any pending requests and queues
            self._pending_key_requests.clear()
            self._pending_envelopes.clear()
            self._pending_encryption_key_requests.clear()
            self._pending_encryption_envelopes.clear()
            self._correlation_to_address.clear()
            raise  # Re-raise to properly handle the cancellation

    async def _register_own_public_keys(self):
        if self._key_manager is None:
            logger.debug("skipping_own_public_keys_registration_no_key_manager")
            return None

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

        if keys:
            await self._key_manager.add_keys(
                keys=keys,
                physical_path=self._node.physical_path,
                system_id=self._node.id,
                origin=DeliveryOriginType.LOCAL,
            )

    async def has_key(self, kid: str) -> bool:
        """Check if a key with the given key ID exists."""
        if self._key_manager is None:
            return False
        return await self._key_manager.has_key(kid)

    async def retry_pending_key_requests_after_attachment(self) -> None:
        """
        Retry any pending key requests that were skipped during attachment
        when the physical path was not yet available.
        """
        if not self._pending_envelopes:
            return

        logger.debug(
            "retrying_pending_key_requests_after_attachment",
            pending_kids=list(self._pending_envelopes.keys()),
        )

        # Collect all kids that need key requests
        kids_to_retry = []
        for kid, envelope_list in self._pending_envelopes.items():
            if envelope_list and kid not in self._pending_key_requests:
                # Find the origin type from the first envelope's context
                _, context = envelope_list[0]
                kids_to_retry.append(
                    (
                        kid,
                        context.origin_type,
                        context.from_system_id or "pending-attachment",
                    )
                )

        # Retry key requests now that physical path is available
        for kid, origin_type, from_system_id in kids_to_retry:
            await self._maybe_request_signing_key(kid, origin_type, from_system_id)
