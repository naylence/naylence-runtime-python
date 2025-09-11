import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Optional

from naylence.fame.core import (
    DeliveryOriginType,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    NodeAttachAckFrame,
    NodeAttachFrame,
    Stickiness,
)
from naylence.fame.node.node_context import FameAuthorizedDeliveryContext
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.keys.attachment_key_validator import (
    AttachmentKeyValidator,
    KeyValidationError,
)
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.sentinel.route_manager import RouteManager
from naylence.fame.sentinel.store.route_store import RouteEntry
from naylence.fame.stickiness.load_balancer_stickiness_manager import (
    LoadBalancerStickinessManager,
)
from naylence.fame.util import logging
from naylence.fame.util.task_spawner import TaskSpawner

logger = logging.getLogger(__name__)


class NodeAttachFrameHandler(TaskSpawner):
    def __init__(
        self,
        *,
        routing_node: RoutingNodeLike,
        route_manager: RouteManager,
        key_manager: Optional[KeyManager] = None,
        attachment_key_validator: Optional[AttachmentKeyValidator] = None,
        stickiness_manager: Optional[LoadBalancerStickinessManager] = None,
        max_ttl_sec: Optional[int] = None,
    ) -> None:
        super().__init__()
        self._routing_node_like = routing_node
        self._route_manager = route_manager
        self._key_manager = key_manager
        self._attachment_key_validator = attachment_key_validator
        self._stickiness_manager = stickiness_manager
        self._max_ttl_sec = max_ttl_sec

    async def accept_node_attach(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext],
    ):
        logger.debug("handling_node_attach_request")
        if context is None:
            raise RuntimeError("missing FameDeliveryContext")

        if not isinstance(envelope.frame, NodeAttachFrame):
            raise ValueError(
                f"Invalid envelope frame. Expected: {NodeAttachFrame}, actual: {{type(envelope.frame)}}"
            )

        frame: NodeAttachFrame = envelope.frame

        if envelope.frame.origin_type not in [
            DeliveryOriginType.DOWNSTREAM,
            DeliveryOriginType.PEER,
        ]:
            raise ValueError(
                f"Invalid attach frame origin type. Expected: {DeliveryOriginType.DOWNSTREAM} "
                f"or {DeliveryOriginType.DOWNSTREAM}, actual:  {envelope.frame.origin_type}"
            )

        attached_system_id = frame.system_id

        connector_config = self._route_manager._pending_route_metadata.pop(attached_system_id, None)
        if connector_config is None:
            raise RuntimeError("Missing pending config metadata")

        pending_route = self._route_manager._pending_routes.pop(attached_system_id, None)
        if not pending_route:
            raise RuntimeError(f"No pending connector for system_id: {attached_system_id}")

        connector, attached, buffer = pending_route
        if connector != context.from_connector:
            raise RuntimeError("Connector in context does not match pending connector")

        attach_expires_at: Optional[datetime] = None
        # if self._max_ttl_sec is not None:
        #     attach_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._max_ttl_sec)

        # Validate child's keys before proceeding with attachment
        child_keys = frame.keys  # Keys provided by the child (if any)

        earliest_key_expiry: Optional[datetime] = None

        # Perform certificate validation on child's keys
        if self._attachment_key_validator:
            try:
                key_infos = await self._attachment_key_validator.validate_keys(child_keys)

                # Check for key expiration and limit attachment TTL accordingly
                if key_infos:
                    earliest_key_expiry = None
                    for key_info in key_infos:
                        if key_info.expires_at is not None:
                            if earliest_key_expiry is None or key_info.expires_at < earliest_key_expiry:
                                earliest_key_expiry = key_info.expires_at

                # Log successful validation with key metadata
                if key_infos:
                    logger.debug(
                        "node_attach_key_validation_passed",
                        system_id=attached_system_id,
                        instance_id=frame.instance_id,
                        correlation_id=envelope.corr_id,
                        validated_keys=len(key_infos),
                        final_attach_expires_at=(
                            attach_expires_at.isoformat() if attach_expires_at else None
                        ),
                    )

            except KeyValidationError as e:
                # Send negative acknowledgment to client
                await self._send_and_notify(
                    connector,
                    self._create_node_attach_ack_env(
                        ok=False,
                        original_env_id=envelope.id,
                        reason=f"Certificate validation failed: {e}",
                        correlation_id=envelope.corr_id,
                        trace_id=envelope.trace_id,
                    ),
                    forward_route=attached_system_id,
                    context=context,
                )

                # Log the key validation failure
                logger.error(
                    "node_attach_key_validation_failed",
                    system_id=attached_system_id,
                    instance_id=frame.instance_id,
                    correlation_id=envelope.corr_id,
                    error_code=e.code,
                    error_message=str(e),
                    kid=e.kid,
                    action="rejecting_attachment",
                )

                # Schedule connection close after a brief delay to allow client to receive the negative ack
                self.spawn(
                    self._close_connection_after_delay(connector, 0.1),
                    name=f"close-invalid-key-connection-{attached_system_id}",
                )

                # Return early to prevent attachment
                return
        else:
            logger.debug(
                "child_key_validation_skipped",
                child_id=attached_system_id,
                reason="no_validator",
            )

        if self._max_ttl_sec is not None:
            attach_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._max_ttl_sec)

        # Apply key expiration limits to attachment TTL
        if earliest_key_expiry is not None:
            if attach_expires_at is not None:
                # Both max TTL and key expiry are set - use the earlier one
                if earliest_key_expiry < attach_expires_at:
                    logger.warning(
                        "attachment_ttl_limited_by_key_expiry",
                        system_id=attached_system_id,
                        instance_id=frame.instance_id,
                        correlation_id=envelope.corr_id,
                        original_attach_expires_at=attach_expires_at.isoformat(),
                        limited_attach_expires_at=earliest_key_expiry.isoformat(),
                    )
                    attach_expires_at = earliest_key_expiry
            else:
                # No max TTL configured, but keys have expiry - use key expiry
                logger.debug(
                    "attachment_ttl_set_by_key_expiry",
                    system_id=attached_system_id,
                    instance_id=frame.instance_id,
                    correlation_id=envelope.corr_id,
                    attach_expires_at=earliest_key_expiry.isoformat(),
                    reason="no_max_ttl_configured",
                )
                attach_expires_at = earliest_key_expiry

        # Note: Logical validation is now handled by centralized authorization
        # in DefaultSecurityManager.on_deliver() before reaching this handler

        # Get security manager for later use

        attached.set()
        # replay buffered envelopes now that we’re attached
        for pending_env in buffer:
            await self._routing_node_like.deliver(
                pending_env,
                FameAuthorizedDeliveryContext(
                    from_connector=connector,
                    from_system_id=attached_system_id,
                    origin_type=frame.origin_type,
                ),
            )
        buffer.clear()

        if frame.origin_type == DeliveryOriginType.DOWNSTREAM:
            if attached_system_id in self._route_manager.downstream_routes:
                logger.warning("rebinding_existing_downstream_route", system_id=attached_system_id)
                old = self._route_manager.downstream_routes[attached_system_id]

                # Calculate old assigned path for key removal
                old_assigned_path = str(
                    PurePosixPath(self._routing_node_like.physical_path) / frame.system_id
                )

                await self._route_manager._safe_stop(old)
                await self._route_manager.unregister_dowstream_route(attached_system_id)

                # Mark this as a rebind for the security manager
                is_rebind = True
            else:
                old_assigned_path = None
                is_rebind = False

            # await self._route_manager.register_downstream_route(attached_system_id, connector)
            assigned_path = frame.assigned_path or str(
                PurePosixPath(self._routing_node_like.physical_path) / frame.system_id
            )

        elif frame.origin_type == DeliveryOriginType.PEER:
            if attached_system_id in self._route_manager._peer_routes:
                logger.warning(f"Rebinding existing peer route for segment '{attached_system_id}'")
                old = self._route_manager._peer_routes[attached_system_id]

                # Calculate old assigned path for key removal
                old_assigned_path = frame.assigned_path or f"/{attached_system_id}"

                await self._route_manager._safe_stop(old)
                await self._route_manager.unregister_peer_route(attached_system_id)

                # Mark this as a rebind for the security manager
                is_rebind = True
            else:
                old_assigned_path = None
                is_rebind = False

            # await self._route_manager.register_peer_route(attached_system_id, connector)
            assigned_path = frame.assigned_path or f"/{attached_system_id}"
        else:
            assert False, "unreachable"

        # Delegate all key management to the event listeners
        await self._routing_node_like._dispatch_event(
            "on_child_attach",
            child_system_id=attached_system_id,
            child_keys=child_keys,
            node_like=self._routing_node_like,
            origin_type=frame.origin_type,
            assigned_path=assigned_path,
            old_assigned_path=old_assigned_path,
            is_rebind=is_rebind,
        )

        if frame.origin_type == DeliveryOriginType.DOWNSTREAM:
            await self._route_manager.register_downstream_route(attached_system_id, connector)
        elif frame.origin_type == DeliveryOriginType.PEER:
            await self._route_manager.register_peer_route(attached_system_id, connector)

        # Negotiate stickiness policy if manager is provided
        negotiated_stickiness = None
        try:
            if self._stickiness_manager is not None:
                negotiated_stickiness = self._stickiness_manager.negotiate(frame.stickiness)
        except Exception as e:
            logger.debug("stickiness_negotiate_skipped", error=str(e))

        node_attach_ack_env = self._create_node_attach_ack_env(
            ok=True,
            original_env_id=envelope.id,
            expires_at=attach_expires_at,
            assigned_path=assigned_path,
            correlation_id=envelope.corr_id,
            trace_id=envelope.trace_id,
            stickiness=negotiated_stickiness,
        )

        logger.debug("sending_node_attach_ack", env_id=node_attach_ack_env.id)

        await self._send_and_notify(connector, node_attach_ack_env, attached_system_id, context)

        # persist durable routes (so we can restore them later)
        if connector_config.durable:
            if frame.origin_type == DeliveryOriginType.DOWNSTREAM:
                route_store = self._route_manager.downstream_route_store
            elif frame.origin_type == DeliveryOriginType.PEER:
                route_store = self._route_manager._peer_route_store
            else:
                assert False

            await route_store.set(
                attached_system_id,
                RouteEntry(
                    system_id=attached_system_id,
                    instance_id=frame.instance_id,
                    assigned_path=assigned_path,
                    connector_config=connector_config,
                    attach_expires_at=attach_expires_at,
                    metadata={},  # No auth metadata since authorization is now centralized
                    durable=connector_config.durable,
                    callback_grants=frame.callback_grants,
                ),
            )

    async def _send_and_notify(
        self,
        connector: FameConnector,
        envelope: FameEnvelope,
        forward_route: str,
        context: Optional[FameDeliveryContext] = None,
    ):
        try:
            await self._routing_node_like._dispatch_envelope_event(
                "on_forward_to_route", self._routing_node_like, forward_route, envelope, context=context
            )
            await connector.send(envelope)
        except Exception as e:
            await self._routing_node_like._dispatch_envelope_event(
                "on_forward_to_route_complete",
                self._routing_node_like,
                forward_route,
                envelope,
                error=e,
                context=context,
            )
            raise
        else:
            await self._routing_node_like._dispatch_envelope_event(
                "on_forward_to_route_complete",
                self._routing_node_like,
                forward_route,
                envelope,
                context=context,
            )

    async def _close_connection_after_delay(self, connector, delay_seconds: float) -> None:
        """Close the connection after a brief delay to allow message delivery."""
        await asyncio.sleep(delay_seconds)
        try:
            # Close the connection with policy violation code (1008)
            # 1008 = Policy Violation - appropriate for authorization failures
            await connector.close(1008, "attach-unauthorized")
            logger.debug("closed_unauthorized_connection")
        except Exception as e:
            # Log but don't re-raise to avoid breaking the spawned task
            logger.error("failed_to_close_unauthorized_connection", error=e, exc_info=True)

    def _create_node_attach_ack_env(
        self,
        *,
        ok: bool,
        original_env_id: str,
        reason: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        assigned_path: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        stickiness: Optional["Stickiness"] = None,
    ) -> FameEnvelope:
        # include real expiry so downstream can warn clients before detaching

        keys = (
            self._routing_node_like.security_manager.get_shareable_keys()
            if self._routing_node_like.security_manager
            else None
        )

        ack = NodeAttachAckFrame(
            target_system_id=self._routing_node_like.id,
            target_physical_path=self._routing_node_like.physical_path,
            ok=ok,
            ref_id=original_env_id,
            reason=reason,
            expires_at=expires_at,
            assigned_path=assigned_path,
            routing_epoch=self._routing_node_like.routing_epoch,
            keys=keys,
        )
        if stickiness is not None:
            ack.stickiness = stickiness
        return FameEnvelope(frame=ack, corr_id=correlation_id, trace_id=trace_id)
