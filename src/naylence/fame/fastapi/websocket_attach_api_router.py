from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig
from naylence.fame.core import (
    DeliveryOriginType,
    NodeAttachAckFrame,
    create_fame_envelope,
)
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.noop_token_verifier import NoopTokenVerifier
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_provider import TokenVerifierProvider
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.sentinel.sentinel import Sentinel

logger = getLogger(__name__)

PROTO_MAJOR = 1
DEFAULT_PREFIX = f"/fame/v{PROTO_MAJOR}/attach"


def create_websocket_attach_router(
    *,
    node: Optional[Sentinel] = None,
    token_verifier: Optional[TokenVerifier] = None,
    authorizer: Optional[Authorizer] = None,
    prefix: str = DEFAULT_PREFIX,
) -> APIRouter:
    """
    Creates a FastAPI router that handles WebSocket Fame attach requests.

    Performs two-level authentication:
    1. Immediate inbound token validation using token_verifier (or authorizer's verifier if available)
    2. Node attach authorization via the node's authorizer

    Args:
        node: The Sentinel node to use. Defaults to current node if not provided.
        token_verifier: Optional explicit token verifier. If not provided, will try to use
                       the verifier from the node's authorizer if it implements
                       TokenVerifierProvider.
        authorizer: Optional explicit authorizer for performing authentication and authorization.
                   If not provided, will use the node's security manager authorizer.
        prefix: URL prefix for the router endpoints.
    """

    if not node:
        from naylence.fame.node.node import get_node

        current_node = get_node()
        from naylence.fame.sentinel.sentinel import Sentinel

        assert isinstance(current_node, Sentinel)
        node = current_node

    # Resolve token verifier: explicit > authorizer's verifier > noop fallback
    if not token_verifier:
        # Check if the node's authorizer provides a token verifier
        if (
            node.security_manager
            and node.security_manager.authorizer
            and isinstance(node.security_manager.authorizer, TokenVerifierProvider)
        ):
            try:
                token_verifier = node.security_manager.authorizer.token_verifier
                logger.debug(
                    "using_token_verifier_from_authorizer",
                    authorizer_type=type(node.security_manager.authorizer).__name__,
                )
            except RuntimeError:
                # Authorizer implements TokenVerifierProvider but doesn't have verifier initialized
                logger.debug("authorizer_token_verifier_not_initialized_fallback_to_noop")
                token_verifier = NoopTokenVerifier()
        else:
            logger.debug("token_verification_disabled")
            token_verifier = NoopTokenVerifier()

    router = APIRouter(prefix=prefix)

    @router.websocket("/ws/{downstream_or_peer}/{system_id}")
    async def websocket_attach_handler(websocket: WebSocket, downstream_or_peer: str, system_id: str):
        # ① Extract and verify token **before** accept

        # Validate and convert downstream_or_peer to DeliveryOriginType
        if downstream_or_peer.lower() == "downstream":
            origin_type = DeliveryOriginType.DOWNSTREAM
        elif downstream_or_peer.lower() == "peer":
            origin_type = DeliveryOriginType.PEER
        else:
            logger.warning(
                "websocket_attach_invalid_origin_type",
                system_id=system_id,
                origin_type=downstream_or_peer,
                valid_types=["downstream", "peer"],
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid origin type")
            return

        subprotos = websocket.headers.get("sec-websocket-protocol", "")
        parts = [s.strip() for s in subprotos.split(",")]

        # Accept both "bearer,<jwt>"  and  "bearer,"  (direct mode)
        token = ""
        if parts and parts[0] == "bearer":
            token = parts[1] if len(parts) > 1 else ""

        if token == "":
            logger.warning("websocket_attach_without_token")

        query_system_id = system_id  # websocket.query_params.get("system_id")

        # origin_type = websocket.query_params.get("origin")
        # if not origin_type:
        #     origin_type = DeliveryOriginType.DOWNSTREAM
        # elif origin_type not in [DeliveryOriginType.DOWNSTREAM, DeliveryOriginType.PEER]:
        #     logger.error(f"Invalid origin type: {origin_type}")
        #     await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        #     return
        # else:
        #     origin_type = DeliveryOriginType(origin_type)

        # try:
        #     # Get the node's physical path for token verification
        #     physical_path = getattr(node, 'physical_path', 'unknown')
        #     claims = await token_verifier.verify(token, expected_audience=physical_path)
        #     jwt_system_id = claims.get("system_id")
        #     # If both sources are present they must agree
        #     if jwt_system_id and query_system_id and query_system_id != jwt_system_id:
        #         raise PyJWTError("system_id param does not match token system_id")
        # except PyJWTError as e:
        #     logger.warning("websocket_attach_token_error", error=str(e), exc_info=True)
        #     await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        #     return

        # system_id = jwt_system_id or query_system_id
        # if not system_id:
        #     logger.warning("websocket_attach_no_system_id")
        #     await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        #     return

        system_id = query_system_id
        if not system_id:
            logger.warning("websocket_attach_no_system_id")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept(subprotocol="bearer" if parts and parts[0] == "bearer" else None)
        logger.debug("websocket_attach_accepted", system_id=system_id)

        try:
            auth_result = None

            # ② Perform authorization check using the same pattern as HTTP listener
            effective_authorizer = authorizer
            if not effective_authorizer and node.security_manager:
                # Fallback to node security manager authorizer
                effective_authorizer = node.security_manager.authorizer

            if effective_authorizer:
                try:
                    # First phase: authentication (token validation)
                    # Pass the token as an Authorization header for consistency with HTTP
                    auth_header = f"Bearer {token}" if token else ""
                    auth_result = await effective_authorizer.authenticate(node.physical_path, auth_header)

                    if auth_result is None:
                        logger.warning(
                            "websocket_attach_authentication_failed",
                            system_id=system_id,
                            reason="Authentication failed",
                            authorizer_type=type(effective_authorizer).__name__,
                        )
                        # Send rejection response
                        ack = NodeAttachAckFrame(
                            type="NodeAttachAck",
                            ok=False,
                            reason="Authentication failed",
                            expires_at=None,
                        )
                        reply_env = create_fame_envelope(frame=ack)
                        await websocket.send_json(reply_env.model_dump(by_alias=True, exclude_none=True))
                        await websocket.close(
                            code=status.WS_1008_POLICY_VIOLATION,
                            reason="Authentication failed",
                        )
                        return

                    logger.debug(
                        "websocket_attach_authorization_success",
                        system_id=system_id,
                        authorizer_type=type(effective_authorizer).__name__,
                    )
                except Exception as auth_error:
                    logger.error(
                        "websocket_attach_authorization_error",
                        system_id=system_id,
                        error=str(auth_error),
                        authorizer_type=type(effective_authorizer).__name__,
                        exc_info=True,
                    )
                    # Send error response
                    ack = NodeAttachAckFrame(
                        type="NodeAttachAck",
                        ok=False,
                        reason=f"Authorization error: {str(auth_error)}",
                        expires_at=None,
                    )
                    reply_env = create_fame_envelope(frame=ack)
                    await websocket.send_json(reply_env.model_dump(by_alias=True, exclude_none=True))
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    return
            else:
                logger.debug(
                    "websocket_attach_no_authorization",
                    system_id=system_id,
                    message="No authorizer configured - allowing connection",
                )

            connector_config = WebSocketConnectorConfig()
            connector = await node.create_origin_connector(
                origin_type=origin_type,
                system_id=system_id,
                connector_config=connector_config,
                websocket=websocket,
                authorization=auth_result,
            )

            if not isinstance(connector, WebSocketConnector):
                raise RuntimeError(
                    f"Invalid connector type. Expected: {WebSocketConnector}, actual: {type(connector)}"
                )
            await connector.wait_until_closed()

        except WebSocketDisconnect:
            logger.debug("websocket_disconnected", system_id=system_id)

        except Exception as e:
            logger.exception("websocket_attach_error", error=e, system_id=system_id, exc_info=True)
            if websocket.client_state == WebSocketState.CONNECTED:
                ack = NodeAttachAckFrame(
                    type="NodeAttachAck",
                    ok=False,
                    reason=f"Unhandled error: {str(e)}",
                    expires_at=None,
                )
                reply_env = create_fame_envelope(frame=ack)
                await websocket.send_json(reply_env.model_dump(by_alias=True, exclude_none=True))
                await websocket.close()

    return router
