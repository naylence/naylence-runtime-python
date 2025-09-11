from __future__ import annotations

import asyncio
import contextlib
from typing import Callable, Optional

from naylence.fame.constants.ttl_constants import DEFAULT_KEY_CORRELATION_TTL_SEC
from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    KeyAnnounceFrame,
    KeyRequestFrame,
)
from naylence.fame.node.binding_manager import BindingManager
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.sentinel.key_correlation_map import KeyCorrelationMap
from naylence.fame.sentinel.route_manager import AddressRouteInfo, RouteManager
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class KeyFrameHandler:
    """Handler for KeyAnnounce and KeyRequest frames in the Sentinel."""

    def __init__(
        self,
        *,
        routing_node: RoutingNodeLike,
        route_manager: RouteManager,
        binding_manager: BindingManager,
        accept_key_announce_parent,
        key_manager: Optional[KeyManager] = None,
    ):
        self._routing_node_like = routing_node
        self._key_manager = key_manager
        self._route_manager = route_manager
        self._binding_manager = binding_manager
        self._accept_key_announce_parent = accept_key_announce_parent

        # Correlation map for routing key announces back to requesters
        self._corr_map = KeyCorrelationMap(ttl_sec=DEFAULT_KEY_CORRELATION_TTL_SEC)
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start(self, spawner: Callable[..., asyncio.Task]) -> None:
        """Start the key frame handler and its background tasks."""
        if not self._cleanup_task:
            self._cleanup_task = spawner(self._corr_map.run_cleanup(), name="key_corr_cleanup")
            logger.debug("key_frame_handler_started")

    async def stop(self) -> None:
        """Stop the key frame handler and cleanup background tasks."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            self._cleanup_task = None
            logger.debug("key_frame_handler_stopped")

    async def accept_key_announce(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """
        Handle incoming KeyAnnounce frames.

        First check if this is a response to a key request we forwarded,
        and if so, route it back to the original requester. Otherwise,
        handle it as a normal key announce.
        """
        assert context and context.origin_type

        # Check if this is a response to a forwarded key request
        frame = envelope.frame
        if isinstance(frame, KeyAnnounceFrame) and envelope.corr_id:
            target_route = self._corr_map.pop(envelope.corr_id)
            if target_route:
                logger.debug(
                    "routing_key_announce_to_original_requester",
                    target_route=target_route,
                )
                # Create a new envelope with the Sentinel's own signature for trust validation
                routing_envelope = self._routing_node_like.envelope_factory.create_envelope(
                    trace_id=envelope.trace_id,
                    frame=frame,  # Keep the same KeyAnnounce frame
                    flow_id=envelope.flow_id,
                    reply_to=envelope.reply_to,
                    corr_id=envelope.corr_id,
                )

                # Forward back to the original requester
                await self._routing_node_like.forward_to_route(target_route, routing_envelope, context)
                return

        # Standard key announce validation and handling
        if not context.origin_type or (
            context.origin_type == DeliveryOriginType.DOWNSTREAM
            and context.from_system_id not in self._route_manager.downstream_routes
        ):
            # TODO: this needs to be checked earlier for all downstream routes
            raise ValueError(
                f"Cannot accept key announce from unknown downstream system {context.from_system_id}"
            )

        if not context.origin_type or (
            context.origin_type == DeliveryOriginType.PEER
            and context.from_system_id not in self._route_manager._peer_routes
        ):
            # TODO: this needs to be checked earlier for all downstream routes
            raise ValueError(
                f"Cannot accept key announce from unknown peer system {context.from_system_id}"
            )

        await self._accept_key_announce_parent(envelope, context)

    async def accept_key_request(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]
    ) -> bool:
        """Handle incoming KeyRequest frames.

        Returns:
            True if the request was handled locally, False if it needs routing through the pipeline.
        """
        assert isinstance(envelope.frame, KeyRequestFrame)
        assert context and context.origin_type
        assert self._key_manager, "KeyManager must be set for KeyRequest handling"

        frame: KeyRequestFrame = envelope.frame

        origin_node_id = self._get_source_system_id(context)
        if not origin_node_id:
            raise ValueError("Missing origin sid")

        # Store correlation mapping for address requests that may be forwarded
        # Since routing decisions now happen in the routing pipeline, we can't predict
        # whether an address will be routed, so we store the correlation for all address requests
        if frame.address and envelope.corr_id:
            self._corr_map.add(envelope.corr_id, origin_node_id)
            logger.debug(
                "stored_key_request_correlation",
                corr_id=envelope.corr_id,
                origin=origin_node_id,
                address=str(frame.address),
            )

        # Check if this is a key request by address or by key ID
        if frame.address:
            handled = await self._handle_key_request_by_address(
                address=frame.address,
                from_seg=origin_node_id,
                physical_path=frame.physical_path,
                delivery_context=context,
                corr_id=envelope.corr_id,
                original_envelope=envelope,  # Pass original envelope to preserve signature
            )

            return handled
        elif frame.kid:
            # Handle key ID requests directly through key manager
            # Check if this involves encryption keys by checking the physical path
            if frame.physical_path:
                try:
                    keys = await self._key_manager.get_keys_for_path(frame.physical_path)
                    encryption_keys = [key for key in keys if key.get("use") == "enc"]
                    if encryption_keys and context:
                        # Set stickiness for encryption key delivery
                        context.stickiness_required = True
                        context.sticky_sid = envelope.sid
                except (AttributeError, ValueError):
                    # If we can't check keys, proceed without stickiness
                    pass

            await self._key_manager.handle_key_request(
                kid=frame.kid,
                from_seg=origin_node_id,
                physical_path=frame.physical_path,
                origin=context.origin_type,
                corr_id=envelope.corr_id,
                original_client_sid=envelope.sid,  # Pass original client SID for stickiness
            )
            return True  # Handled locally by key manager
        else:
            raise ValueError("KeyRequest must specify either kid or address")

    def _get_address_route_info(self, address: FameAddress) -> Optional[AddressRouteInfo]:
        """Get route info for an address, checking both downstream and peer routes."""
        # Check downstream routes first (exact matches)
        if address in self._route_manager._downstream_addresses_routes:
            return self._route_manager._downstream_addresses_routes[address]

        # Check peer routes (exact matches)
        if address in self._route_manager._peer_addresses_routes:
            peer_segment = self._route_manager._peer_addresses_routes[address]
            return AddressRouteInfo(segment=peer_segment, physical_path=None, encryption_key_id=None)

        return None

    async def _handle_key_request_by_address(
        self,
        address: FameAddress,
        from_seg: str,
        *,
        physical_path: str | None,
        delivery_context: Optional[FameDeliveryContext] = None,
        corr_id: Optional[str] = None,
        original_envelope: Optional[FameEnvelope] = None,
    ) -> bool:
        """
        Handle key request by address with the following logic:
        1. Check if there's a downstream/peer route for this address and forward if found
        2. Check if there's a local binding for this address and try to find encryption keys
        3. Check if there's an address binding for this address and if it contains encryption_key_id
        4. If not, check if the address binding contains a physical path and try lookup by path
        5. Try to resolve logical address to pool member and forward to pool member if found
        6. If all unsuccessful, propagate the key request upstream
        """
        logger.trace("handling_key_request_by_address", address=address, corr_id=corr_id)
        assert self._key_manager, "KeyManager must be set for KeyRequest handling"

        assert delivery_context and delivery_context.origin_type, (
            "Delivery context must have origin type for key request handling"
        )

        # Step 1: Check if there's a downstream or peer route for this address
        route_info = self._get_address_route_info(address)
        if route_info and route_info.segment:
            logger.debug(
                "key_request_needs_routing",
                address=address,
                segment=route_info.segment,
                corr_id=corr_id,
            )
            # Don't forward directly - let the routing pipeline handle this
            # This ensures deterministic SID routing is applied
            return False

        # Step 2: Check if there's a local binding for this address first
        local_binding = self._binding_manager.get_binding(address)
        if local_binding:
            logger.trace("found_local_binding", address=address, binding=local_binding)

            # For local bindings, use the routing node's own physical path
            local_physical_path = self._routing_node_like.physical_path

            if local_physical_path:
                try:
                    # Try to find encryption keys for the local physical path
                    keys = await self._key_manager.get_keys_for_path(local_physical_path)
                    encryption_keys = [k for k in keys if k.get("use") == "enc"]

                    if encryption_keys:
                        logger.trace(
                            "found_encryption_keys_for_local_binding",
                            path=local_physical_path,
                            count=len(encryption_keys),
                        )
                        # Use the first encryption key for the response
                        first_enc_key = encryption_keys[0]
                        found_key_id = first_enc_key.get("kid")
                        if found_key_id:
                            # Set stickiness for encryption key delivery
                            if delivery_context:
                                delivery_context.stickiness_required = True
                                delivery_context.sticky_sid = (
                                    original_envelope.sid if original_envelope else from_seg
                                )

                            await self._key_manager.handle_key_request(
                                kid=found_key_id,
                                from_seg=from_seg,
                                physical_path=local_physical_path,
                                origin=delivery_context.origin_type,
                                corr_id=corr_id,
                                original_client_sid=(original_envelope.sid if original_envelope else None),
                            )

                        return True  # Handled locally
                except (ValueError, AttributeError) as e:
                    logger.trace(
                        "key_lookup_for_local_binding_failed",
                        path=local_physical_path,
                        error=str(e),
                    )

        # Step 3: Check if there's an address route for this address
        route_info = None

        # Check downstream routes first
        if address in self._route_manager._downstream_addresses_routes:
            route_info = self._route_manager._downstream_addresses_routes[address]
            logger.trace("found_downstream_address_route", address=address, route_info=route_info)

        # Check peer routes if not found in downstream
        elif address in self._route_manager._peer_addresses_routes:
            peer_segment = self._route_manager._peer_addresses_routes[address]
            # For peer routes, we create a minimal route info
            route_info = AddressRouteInfo(
                segment=peer_segment,
                physical_path=physical_path,
                encryption_key_id=None,
            )
            logger.trace("found_peer_address_route", address=address, segment=peer_segment)

        encryption_key_id = None
        lookup_physical_path = physical_path

        if route_info:
            # Step 3a: Check if we have encryption_key_id directly
            if route_info.encryption_key_id:
                encryption_key_id = route_info.encryption_key_id
                logger.trace(
                    "found_encryption_key_id_in_route",
                    address=address,
                    key_id=encryption_key_id,
                )

                try:
                    # Set stickiness for encryption key delivery when found via route
                    if delivery_context:
                        delivery_context.stickiness_required = True
                        delivery_context.sticky_sid = (
                            original_envelope.sid if original_envelope else from_seg
                        )

                    await self._key_manager.handle_key_request(
                        kid=encryption_key_id,
                        from_seg=from_seg,
                        physical_path=route_info.physical_path or lookup_physical_path,
                        origin=delivery_context.origin_type,
                        corr_id=corr_id,
                        original_client_sid=(original_envelope.sid if original_envelope else None),
                    )

                    return True  # Handled locally
                except ValueError as e:
                    logger.trace(
                        "key_lookup_by_encryption_key_id_failed",
                        key_id=encryption_key_id,
                        error=str(e),
                    )

            # Step 3b: Try physical path lookup if encryption_key_id didn't work
            if route_info.physical_path:
                lookup_physical_path = route_info.physical_path
                logger.trace("attempting_key_lookup_by_physical_path", path=lookup_physical_path)

                try:
                    # Try to find keys for this physical path
                    keys = await self._key_manager.get_keys_for_path(lookup_physical_path)
                    if keys:
                        # Found keys by physical path - only handle encryption keys
                        encryption_keys = [k for k in keys if k.get("use") == "enc"]

                        if encryption_keys:
                            logger.trace(
                                "found_encryption_keys_by_physical_path",
                                path=lookup_physical_path,
                                count=len(encryption_keys),
                            )
                            # Use the first encryption key for the response
                            first_enc_key = encryption_keys[0]
                            found_key_id = first_enc_key.get("kid")
                            if found_key_id:
                                # Set stickiness for encryption key delivery
                                if delivery_context:
                                    delivery_context.stickiness_required = True
                                    delivery_context.sticky_sid = (
                                        original_envelope.sid if original_envelope else from_seg
                                    )

                                await self._key_manager.handle_key_request(
                                    kid=found_key_id,
                                    from_seg=from_seg,
                                    physical_path=lookup_physical_path,
                                    origin=delivery_context.origin_type,
                                    corr_id=corr_id,
                                    original_client_sid=(
                                        original_envelope.sid if original_envelope else None
                                    ),
                                )

                                return True  # Handled locally
                except (ValueError, AttributeError) as e:
                    logger.trace(
                        "key_lookup_by_physical_path_failed",
                        path=lookup_physical_path,
                        error=str(e),
                    )

        # Step 3c: Try to extract physical path from the address itself
        if not route_info or not route_info.physical_path:
            # Parse the address to extract physical path
            # Addresses like "rpc-id@/path/to/node" contain the physical path after @
            address_str = str(address)
            if "@" in address_str:
                _, path_part = address_str.split("@", 1)
                if path_part.startswith("/"):
                    # This looks like a physical path, try to find keys for it
                    extracted_path = path_part
                    logger.trace(
                        "extracted_physical_path_from_address",
                        address=address_str,
                        extracted_path=extracted_path,
                    )

                    try:
                        # Try to find encryption keys for this physical path
                        keys = await self._key_manager.get_keys_for_path(extracted_path)
                        encryption_keys = [k for k in keys if k.get("use") == "enc"]

                        if encryption_keys:
                            logger.trace(
                                "found_encryption_keys_by_extracted_path",
                                path=extracted_path,
                                count=len(encryption_keys),
                            )
                            # Use the first encryption key for the response
                            first_enc_key = encryption_keys[0]
                            found_key_id = first_enc_key.get("kid")
                            if found_key_id:
                                # Set stickiness for encryption key delivery
                                if delivery_context:
                                    delivery_context.stickiness_required = True
                                    delivery_context.sticky_sid = (
                                        original_envelope.sid if original_envelope else from_seg
                                    )

                                await self._key_manager.handle_key_request(
                                    kid=found_key_id,
                                    from_seg=from_seg,
                                    physical_path=extracted_path,
                                    origin=delivery_context.origin_type,
                                    corr_id=corr_id,
                                    original_client_sid=(
                                        original_envelope.sid if original_envelope else None
                                    ),
                                )

                            return True  # Handled locally
                    except (ValueError, AttributeError) as e:
                        logger.trace(
                            "key_lookup_by_extracted_path_failed",
                            path=extracted_path,
                            error=str(e),
                        )

        # Step 4: Let the routing pipeline handle pool member resolution and upstream forwarding
        # This ensures consistent SID routing for all KeyRequest frames
        logger.trace("delegating_to_routing_pipeline", address=address, corr_id=corr_id)
        return False

    def _get_source_system_id(self, context: Optional[FameDeliveryContext]):
        source_system_id = None
        if context and context.from_system_id:
            source_system_id = context.from_system_id
        return source_system_id
