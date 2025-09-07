from __future__ import annotations

import asyncio
from typing import Any, List, Optional

from naylence.fame.core import (
    DeliveryOriginType,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    NodeAttachAckFrame,
    NodeAttachFrame,
    NodeWelcomeFrame,
    generate_id,
)
from naylence.fame.node.admission.node_attach_client import AttachInfo, NodeAttachClient
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.keys.attachment_key_validator import (
    AttachmentKeyValidator,
    KeyValidationError,
)
from naylence.fame.stickiness.replica_stickiness_manager import ReplicaStickinessManager
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultNodeAttachClient(NodeAttachClient):
    """
    Default implementation of FameNodeAttachClient.
    Buffers incoming envelopes until ACK is received, then switches to final handler.
    """

    def __init__(
        self,
        timeout_ms: int = 10000,
        attachment_key_validator: Optional[AttachmentKeyValidator] = None,
        replica_stickiness_manager: Optional[ReplicaStickinessManager] = None,
    ):
        self._buffer: List[FameEnvelope] = []
        self._in_handshake = False
        self._timeout_ms = timeout_ms
        self._attachment_key_validator = attachment_key_validator
        self._replica_stickiness_manager = replica_stickiness_manager

    async def attach(
        self,
        node: NodeLike,
        origin_type: DeliveryOriginType,
        connector: FameConnector,
        welcome_frame: NodeWelcomeFrame,
        final_handler: FameEnvelopeHandler,
        keys: Optional[list[dict]] = None,
        callback_grants: Optional[List[dict[str, Any]]] = None,
    ) -> AttachInfo:
        self._in_handshake = True

        # 1) install interim handler
        async def interim_handler(env: FameEnvelope, _ctx: Optional[Any] = None):
            if self._in_handshake:
                self._buffer.append(env)
                return None
            else:
                return await final_handler(env, None)

        if hasattr(connector, "replace_handler"):
            await connector.replace_handler(interim_handler)
        else:
            raise RuntimeError("Connector does not support handler replacement")

        # 2) send attach request
        attach_req = NodeAttachFrame(
            origin_type=origin_type,
            system_id=welcome_frame.system_id,
            instance_id=welcome_frame.instance_id,
            assigned_path=welcome_frame.assigned_path,
            capabilities=welcome_frame.accepted_capabilities,
            accepted_logicals=welcome_frame.accepted_logicals,
            keys=keys,
            callback_grants=callback_grants,
        )

        # Opaque stickiness offer via explicitly provided ReplicaStickinessManager, if any
        try:
            if self._replica_stickiness_manager is not None:
                offer = self._replica_stickiness_manager.offer()
                if offer is not None:
                    attach_req.stickiness = offer
        except Exception as e:
            logger.debug("stickiness_offer_skipped", error=str(e))

        corr_id = generate_id()
        trace_id = generate_id()
        env = FameEnvelope(frame=attach_req, corr_id=corr_id, trace_id=trace_id)

        local_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)

        processed_env: Optional[FameEnvelope] = None
        try:
            processed_env = await node._dispatch_envelope_event(
                "on_forward_upstream", node, env, context=local_context
            )
            if processed_env is not None:
                await connector.send(processed_env)
            else:
                raise RuntimeError("Envelope was blocked by on_forward_upstream event")
        except Exception as e:
            # Capture the exception for the completion event
            await node._dispatch_envelope_event(
                "on_forward_upstream_complete", node, processed_env or env, error=e, context=local_context
            )
            # Re-rasie the original exception
            raise
        else:
            # No exception occurred - call completion event without error
            await node._dispatch_envelope_event(
                "on_forward_upstream_complete", node, processed_env or env, context=local_context
            )

        # 3) wait for ACK
        ack_env = await self._await_ack(connector)

        node_attach_ack_frame = ack_env.frame

        context = FameDeliveryContext(
            from_connector=connector,
            from_system_id=getattr(node_attach_ack_frame, "target_system_id", "unknown"),
            origin_type=DeliveryOriginType.UPSTREAM,
        )

        await node._dispatch_envelope_event("on_envelope_received", node, ack_env, context)

        assert isinstance(node_attach_ack_frame, NodeAttachAckFrame)

        if corr_id != ack_env.corr_id:
            raise RuntimeError(
                f"Attach rejected, invalid correlation id. Expected: {corr_id}, actual: {ack_env.corr_id}"
            )
        if not node_attach_ack_frame.ok:
            raise RuntimeError(f"Attach rejected: {node_attach_ack_frame.reason or 'unknown'}")

        # Validate parent's certificates before accepting the attachment
        parent_keys = node_attach_ack_frame.keys
        parent_id = node_attach_ack_frame.target_system_id or "unknown"

        if self._attachment_key_validator:
            try:
                key_infos = await self._attachment_key_validator.validate_keys(parent_keys)

                # Log successful validation with key metadata
                if key_infos:
                    logger.debug(
                        "parent_certificate_validation_passed",
                        parent_id=parent_id,
                        correlation_id=corr_id,
                        validated_keys=len(key_infos),
                    )

            except KeyValidationError as e:
                logger.error(
                    "parent_certificate_validation_failed",
                    parent_id=parent_id,
                    correlation_id=corr_id,
                    error_code=e.code,
                    error_message=str(e),
                    kid=e.kid,
                    action="rejecting_attachment",
                )
                raise RuntimeError(f"Parent certificate validation failed: {e}")
        else:
            logger.debug(
                "parent_certificate_validation_skipped",
                parent_id=parent_id,
                reason="no_validator",
            )

        logger.debug(
            "processing_node_attach_ack",
            parent_id=node_attach_ack_frame.target_system_id,
        )
        # 4) switch to final handler and drain buffer
        self._in_handshake = False
        await connector.replace_handler(final_handler)
        for env in self._buffer:
            await final_handler(env, None)

        self._buffer.clear()

        assigned_path = welcome_frame.assigned_path or node_attach_ack_frame.assigned_path

        assert assigned_path

        target_physical_path = (
            node_attach_ack_frame.target_physical_path or welcome_frame.target_physical_path
        )

        assert target_physical_path

        assert node_attach_ack_frame.target_system_id, (
            "Target system ID must be set in NodeAttachAckFrame on success"
        )
        # Pass negotiated policy (if any) to the replica-side stickiness manager
        try:
            if self._replica_stickiness_manager is not None:
                self._replica_stickiness_manager.accept(getattr(node_attach_ack_frame, "stickiness", None))
        except Exception as e:
            logger.debug("stickiness_accept_skipped", error=str(e))

        # 5) return info
        return AttachInfo(
            system_id=welcome_frame.system_id,
            target_system_id=node_attach_ack_frame.target_system_id,  # or welcome_frame.target_system_id,
            target_physical_path=target_physical_path,
            assigned_path=assigned_path,
            accepted_logicals=welcome_frame.accepted_logicals,
            attach_expires_at=(
                node_attach_ack_frame.expires_at if node_attach_ack_frame.expires_at else None
            ),
            routing_epoch=node_attach_ack_frame.routing_epoch,
            connector=connector,
            parent_keys=node_attach_ack_frame.keys,
        )

    async def _await_ack(self, connector: FameConnector) -> FameEnvelope:
        start = asyncio.get_event_loop().time()
        deadline = start + self._timeout_ms / 1000
        while asyncio.get_event_loop().time() < deadline:
            if not connector.state.is_active:
                # Connector closed while waiting for ACK - provide detailed error
                error_msg = "Connector closed while waiting for NodeAttachAck"

                if connector.close_code is not None:
                    error_msg += f" (code={connector.close_code}"
                    if connector.close_reason:
                        error_msg += f", reason={connector.close_reason}"
                    error_msg += ")"

                if connector.last_error:
                    error_msg += f" - {type(connector.last_error).__name__}: {connector.last_error}"

                raise RuntimeError(error_msg)

            if self._buffer:
                envelope = self._buffer.pop(0)  # pop **first**, then inspect
                if isinstance(envelope.frame, NodeAttachAckFrame):
                    return envelope
                logger.error(
                    "Unexpected frame during handshake: %s",
                    type(envelope.frame).__name__,
                )
                continue
            await asyncio.sleep(0.02)

        raise TimeoutError("Timeout waiting for NodeAttachAck")
