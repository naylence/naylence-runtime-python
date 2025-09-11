from __future__ import annotations

from typing import Dict, Optional, Set

from naylence.fame.core import (
    AddressBindAckFrame,
    AddressBindFrame,
    AddressUnbindAckFrame,
    AddressUnbindFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    parse_address,
    parse_address_components,
)
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.sentinel.route_manager import AddressRouteInfo, RouteManager
from naylence.fame.sentinel.router import PoolKey
from naylence.fame.util.logging import getLogger
from naylence.fame.util.logicals_util import is_pool_logical
from naylence.fame.util.util import normalize_path

logger = getLogger(__name__)


class AddressBindFrameHandler:
    """Handler for AddressBind and AddressUnbind frames in the Sentinel."""

    def __init__(
        self,
        *,
        routing_node: RoutingNodeLike,
        route_manager: RouteManager,
        upstream_connector,
    ):
        self._routing_node_like = routing_node
        self._route_manager = route_manager
        self._pools: Dict[PoolKey, Set[str]] = {}
        self._upstream_connector = upstream_connector

    @property
    def pools(self) -> Dict[PoolKey, Set[str]]:
        """Access to pools for external components like RouterState."""
        return self._pools

    async def accept_address_bind(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming AddressBind frames."""
        assert context and context.origin_type

        frame = envelope.frame
        if not isinstance(frame, AddressBindFrame):
            raise ValueError(f"Expected AddressBindFrame, got {type(frame)}")

        source_system_id = self._get_source_system_id(context)

        if not source_system_id:
            return

        if (
            context.origin_type == DeliveryOriginType.DOWNSTREAM
            and source_system_id not in self._route_manager.downstream_routes
        ):
            raise ValueError(
                f"Cannot accept address bind from unknown downstream system {source_system_id}"
            )

        if (
            context.origin_type == DeliveryOriginType.PEER
            and source_system_id not in self._route_manager._peer_routes
        ):
            raise ValueError(f"Cannot accept address bind from unknown peer system {source_system_id}")

        # Parse address components to handle both path-based and host-based addresses
        name, location = parse_address(frame.address)

        # Determine if this is a host-based or path-based address
        try:
            _, host, path = parse_address_components(frame.address)
            is_host_based = host is not None
        except Exception:
            is_host_based = False
            host = None

        # Check for pool binding
        is_pool_bind = False
        pool_key = None

        if is_host_based and host and is_pool_logical(host):
            # Host-based pool pattern like "math@*.fame.fabric"
            is_pool_bind = True
            # Store the full wildcard pattern, not just the base
            pool_key = (name, host)  # Keep "*.fame.fabric" not just "fame.fabric"
        elif not is_host_based and (location.endswith("/*") or location.endswith("/**")):
            # Legacy path-based pool pattern like "math@/api/*"
            is_pool_bind = True
            root = normalize_path(location[:-2] if location.endswith("/*") else location[:-3])
            pool_key = (name, root)

        if is_pool_bind and pool_key:
            # ── this is a POOL bind ─────────────────────────────
            pool = self._pools.setdefault(pool_key, set())
            pool.add(source_system_id)

            ack = AddressBindAckFrame(address=frame.address, ok=True, ref_id=envelope.id)
        else:
            # ── this is an EXACT bind ────────────────────────────
            # Get physical path from the route store
            physical_path = None

            if context.origin_type == DeliveryOriginType.DOWNSTREAM:
                try:
                    route_entry = await self._route_manager._downstream_route_store.get(source_system_id)
                    if route_entry:
                        physical_path = route_entry.assigned_path
                except Exception:
                    logger.debug("Could not retrieve route entry for physical path resolution")

            # Create route info without encryption key (resolved when needed)
            route_info = AddressRouteInfo(
                segment=source_system_id,
                physical_path=physical_path,
                encryption_key_id=frame.encryption_key_id,
            )

            if context.origin_type == DeliveryOriginType.DOWNSTREAM:
                self._route_manager._downstream_addresses_routes[frame.address] = route_info
            elif context.origin_type == DeliveryOriginType.PEER:
                # EXACT bind from a peer
                self._route_manager._peer_addresses_routes[frame.address] = source_system_id
            else:
                assert False, "unreachable"

            ack = AddressBindAckFrame(address=frame.address, ok=True, ref_id=envelope.id)

        if context.origin_type == DeliveryOriginType.DOWNSTREAM:
            # send ACK back to the downstream
            # Create a LOCAL context for the ACK while preserving signature mirroring information
            routing_node_id = getattr(self._routing_node_like, "id", None)
            if routing_node_id is None or not isinstance(routing_node_id, str):
                # Fallback to a default system identifier if no valid ID is available
                routing_node_id = "sentinel"

            ack_context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL,
                from_system_id=routing_node_id,
                security=context.security,  # Preserve original security context for signature mirroring
            )
            # Mark as response to enable signature mirroring
            ack_context.meta = {"message-type": "response"}

            await self._routing_node_like.forward_to_route(
                source_system_id,
                self._routing_node_like.envelope_factory.create_envelope(
                    frame=ack, corr_id=envelope.corr_id
                ),
                ack_context,
            )

        # ALWAYS propagate address binds upstream - no more "first" shortcut
        # This ensures parent nodes have complete and up-to-date routing information
        if self._upstream_connector():
            await self._routing_node_like.forward_upstream(envelope, context)

        await self._routing_node_like.forward_to_peers(
            envelope, None, exclude_peers=[source_system_id], context=context
        )

        logger.debug("address_bound", address=frame.address, segment=source_system_id)

    async def accept_address_unbind(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Handle incoming AddressUnbind frames."""
        frame = envelope.frame
        if not isinstance(frame, AddressUnbindFrame):
            raise ValueError(f"Expected AddressUnbindFrame, got {type(frame)}")

        seg = self._get_source_system_id(context)

        if not seg:
            return

        # Parse address components to handle both path-based and host-based addresses
        name, location = parse_address(frame.address)

        # Determine if this is a host-based or path-based address
        try:
            _, host, path = parse_address_components(frame.address)
            is_host_based = host is not None
        except Exception:
            is_host_based = False
            host = None

        # Check for pool unbinding
        is_pool_unbind = False
        pool_key = None

        if is_host_based and host and is_pool_logical(host):
            # Host-based pool pattern like "math@*.fame.fabric"
            is_pool_unbind = True
            # Use the full wildcard pattern, not just the base
            pool_key = (name, host)  # Keep "*.fame.fabric" not just "fame.fabric"
        elif not is_host_based and (location.endswith("/*") or location.endswith("/**")):
            # Legacy path-based pool pattern like "math@/api/*"
            is_pool_unbind = True
            root = normalize_path(location[:-2] if location.endswith("/*") else location[:-3])
            pool_key = (name, root)

        if is_pool_unbind and pool_key:
            # Remove from POOL
            pool = self._pools.get(pool_key)
            if pool and seg in pool:
                pool.remove(seg)
                if not pool:
                    # last unbind → remove the key entirely
                    self._pools.pop(pool_key, None)
                if self._upstream_connector():
                    await self._routing_node_like.forward_upstream(envelope, context)
        else:
            # Remove an EXACT bind
            route_info = self._route_manager._downstream_addresses_routes.get(frame.address)
            if route_info and route_info.segment == seg:
                self._route_manager._downstream_addresses_routes.pop(frame.address, None)
                # Also remove from legacy table if it exists (for backward compatibility with tests)
                legacy_table = getattr(self._route_manager, "_downstream_addresses_legacy", None)
                if legacy_table is not None:
                    legacy_table.pop(frame.address, None)
                if self._upstream_connector():
                    await self._routing_node_like.forward_upstream(envelope, context)

        # Send ACK back to the downstream if it's a downstream request
        if context and context.origin_type == DeliveryOriginType.DOWNSTREAM:
            ack = AddressUnbindAckFrame(address=frame.address, ok=True, ref_id=envelope.id)

            # Create a LOCAL context for the ACK while preserving signature mirroring information
            routing_node_id = getattr(self._routing_node_like, "id", None)
            if routing_node_id is None or not isinstance(routing_node_id, str):
                # Fallback to a default system identifier if no valid ID is available
                routing_node_id = "sentinel"

            ack_context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL,
                from_system_id=routing_node_id,
                security=context.security,  # Preserve original security context for signature mirroring
            )
            # Mark as response to enable signature mirroring
            ack_context.meta = {"message-type": "response"}

            await self._routing_node_like.forward_to_route(
                seg,
                self._routing_node_like.envelope_factory.create_envelope(
                    frame=ack, corr_id=envelope.corr_id
                ),
                ack_context,
            )

        logger.debug("address_unbound", address=frame.address, segment=seg)

    def _get_source_system_id(self, context: Optional[FameDeliveryContext]):
        source_system_id = None
        if context and context.from_system_id:
            source_system_id = context.from_system_id
        return source_system_id
