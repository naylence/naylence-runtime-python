from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState

from naylence.fame.connector.transport_listener import TransportListener
from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_connector_factory import WebSocketConnectorConfig
from naylence.fame.core import (
    AuthorizationContext,
    DeliveryOriginType,
    NodeAttachAckFrame,
    create_fame_envelope,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.noop_token_verifier import NoopTokenVerifier
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_provider import TokenVerifierProvider
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.connector.http_server import HttpServer
    from naylence.fame.node.node_like import NodeLike
    from naylence.fame.node.routing_node_like import RoutingNodeLike

logger = getLogger(__name__)


class WebSocketListener(TransportListener, NodeEventListener):
    """
    WebSocket listener that provides WebSocket attach endpoints for WebSocket connectors.

    This listener creates WebSocket endpoints on the shared HTTP server that handle:
    - WebSocket node attachment and handshake
    - Real-time bidirectional communication
    - Token-based authentication
    - Connector lifecycle management
    """

    def __init__(
        self,
        *,
        http_server: HttpServer,
        token_verifier: Optional[TokenVerifier] = None,
        authorizer: Optional[Authorizer] = None,
        **kwargs,
    ):
        global _last_websocket_listener_instance
        self._http_server = http_server
        self._token_verifier = token_verifier
        self._authorizer = authorizer  # Per-listener authorizer
        self._public_url: Optional[str] = None  # Set from node.public_url in on_node_initialized
        self._router_registered = False
        self._node: Optional[NodeLike] = None
        # Register this instance for test helper functions
        _last_websocket_listener_instance = self

    # ── NodeEventListener interface ─────────────────────────────────────────

    async def on_node_initialized(self, node: NodeLike) -> None:
        """Register WebSocket routes with the HTTP server when node is initialized."""
        if self._router_registered:
            return

        self._node = node

        # Get public_url from node
        self._public_url = node.public_url

        logger.debug("registering_websocket_routes", class_name=self.__class__.__name__)

        # Create and register the router
        router = await self.create_router()
        self._http_server.include_router(router)
        self._router_registered = True

        logger.debug("websocket_routes_registered", base_url=self._http_server.actual_base_url)

    async def on_node_stopped(self, node: NodeLike) -> None:
        """Clear all WebSocket connectors when node stops."""
        # Connectors are managed by the RoutingNodeLike implementation
        self._router_registered = False

    async def on_node_started(self, node: NodeLike) -> None:
        """Node has started - no special action needed for WebSocket listener."""
        pass

    # ── TransportListener interface ──────────────────────────────────────────

    async def start(self) -> None:
        """Start the transport listener (HTTP server managed externally)."""
        # HTTP server lifecycle is managed externally
        pass

    async def stop(self) -> None:
        """Stop the transport listener (HTTP server managed externally)."""
        # HTTP server lifecycle is managed externally
        pass

    def get_callback_grant(self) -> Optional[Any]:
        """Get connector descriptor for this listener."""
        return {
            "type": "WebSocketListener",
            "base_url": self.base_url,
            "host": self.advertised_host,
            "port": self.advertised_port,
        }

    def as_callback_grant(self) -> Optional[dict[str, Any]]:
        """Return connector configuration for reverse connections."""
        if not self.base_url:
            return None

        # Convert HTTP(S) base URL to WebSocket URL
        ws_url = self.base_url.replace("http://", "ws://").replace("https://", "wss://")

        return {
            "type": "WebSocketStatelessConnector",
            "url": f"{ws_url}{self.upstream_endpoint}",
        }

    # ── Public API ───────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Check if the HTTP server is running."""
        return self._http_server.is_running

    @property
    def base_url(self) -> Optional[str]:
        """Get the base URL for this WebSocket listener."""
        # Use public URL from node config if available, otherwise fall back to actual server URL
        return self._public_url or self._http_server.actual_base_url

    @property
    def attach_prefix(self) -> str:
        """Get the WebSocket attach route prefix for this listener."""
        return "/fame/v1/attach"

    @property
    def upstream_endpoint(self) -> str:
        """Get the upstream WebSocket endpoint path."""
        # WebSocket uses /ws/upstream under the attach prefix
        return f"{self.attach_prefix}/ws/upstream"

    @property
    def advertised_host(self) -> Optional[str]:
        """Get the advertised host."""
        return self._http_server.actual_host

    @property
    def advertised_port(self) -> Optional[int]:
        """Get the advertised port."""
        return self._http_server.actual_port

    @property
    def http_server(self) -> HttpServer:
        """Get the injected HTTP server."""
        return self._http_server

    # ── WebSocket Router Creation ────────────────────────────────────────────

    async def create_router(self) -> APIRouter:
        """Create the FastAPI router for WebSocket endpoints."""
        assert self._node
        router = APIRouter(prefix=self.attach_prefix)

        # Resolve token verifier if not provided
        token_verifier = self._token_verifier
        if not token_verifier:
            # Check if the node's authorizer provides a token verifier
            if (
                self._node.security_manager
                and self._node.security_manager.authorizer
                and isinstance(self._node.security_manager.authorizer, TokenVerifierProvider)
            ):
                try:
                    token_verifier = self._node.security_manager.authorizer.token_verifier
                    logger.debug(
                        "using_token_verifier_from_authorizer",
                        authorizer_type=type(self._node.security_manager.authorizer).__name__,
                    )
                except RuntimeError:
                    # Authorizer implements TokenVerifierProvider but doesn't have verifier initialized
                    logger.debug("authorizer_token_verifier_not_initialized_fallback_to_noop")
                    token_verifier = NoopTokenVerifier()
            else:
                logger.debug("token_verification_disabled")
                token_verifier = NoopTokenVerifier()

        @router.websocket("/ws/{downstream_or_peer}/{system_id}")
        async def websocket_attach_handler(websocket: WebSocket, downstream_or_peer: str, system_id: str):
            """
            Handle WebSocket attach requests.

            Performs two-level authentication:
            1. Immediate inbound token validation using token_verifier
            2. Node attach authorization via the node's authorizer
            """

            assert self._node

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

            # ① Extract and verify token **before** accept
            subprotos = websocket.headers.get("sec-websocket-protocol", "")
            parts = [s.strip() for s in subprotos.split(",")]

            # Accept both "bearer,<jwt>" and "bearer," (direct mode)
            token = ""
            if parts and parts[0] == "bearer":
                token = parts[1] if len(parts) > 1 else ""

            if token == "":
                logger.warning("websocket_attach_without_token")

            # system_id = query_system_id
            if not system_id:
                logger.warning("websocket_attach_no_system_id")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            elif self._node and self._node.id == system_id:
                logger.error("websocket_self_attachment_attempt", system_id=system_id)
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            await websocket.accept(subprotocol="bearer" if parts and parts[0] == "bearer" else None)
            logger.debug("websocket_attach_accepted", system_id=system_id)

            try:
                auth_result = None

                # ② Perform authorization check using the same pattern as HTTP listener
                authorizer = self._authorizer
                if not authorizer and self._node.security_manager:
                    # Fallback to node security manager authorizer
                    authorizer = self._node.security_manager.authorizer

                if authorizer:
                    try:
                        # First phase: authentication (token validation)
                        # Pass the token as an Authorization header for consistency with HTTP
                        auth_header = f"Bearer {token}" if token else ""
                        auth_result = await authorizer.authenticate(auth_header)

                        if auth_result is None:
                            logger.warning(
                                "websocket_attach_authentication_failed",
                                system_id=system_id,
                                reason="Authentication failed",
                                authorizer_type=type(authorizer).__name__,
                            )
                            # Send rejection response
                            ack = NodeAttachAckFrame(
                                type="NodeAttachAck",
                                ok=False,
                                reason="Authentication failed",
                                expires_at=None,
                            )
                            reply_env = create_fame_envelope(frame=ack)
                            await websocket.send_json(
                                reply_env.model_dump(by_alias=True, exclude_none=True)
                            )
                            await websocket.close(
                                code=status.WS_1008_POLICY_VIOLATION,
                                reason="Authentication failed",
                            )
                            return

                        logger.debug(
                            "websocket_attach_authorization_success",
                            system_id=system_id,
                            authorizer_type=type(authorizer).__name__,
                        )
                    except Exception as auth_error:
                        logger.error(
                            "websocket_attach_authorization_error",
                            system_id=system_id,
                            error=str(auth_error),
                            authorizer_type=type(authorizer).__name__,
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

                # Register the connector
                # Create WebSocket connector
                connector = await self._create_websocket_connector(
                    system_id=system_id,
                    websocket=websocket,
                    origin_type=origin_type,
                    node=self._node,
                    authorization=auth_result,
                )

                # Connector will be managed by the RoutingNodeLike implementation (route manager)
                logger.debug("websocket_connector_registered", system_id=system_id)

                # Wait until the connection is closed
                await connector.wait_until_closed()

            except WebSocketDisconnect:
                logger.debug("websocket_disconnected", system_id=system_id)

            except Exception as e:
                logger.exception(
                    "websocket_attach_error",
                    error=e,
                    system_id=system_id,
                    exc_info=True,
                )
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

            finally:
                # Cleanup connector registration
                # Connectors are managed by the RoutingNodeLike implementation
                logger.debug("websocket_connector_unregistered", system_id=system_id)

        @router.get("/health")
        async def websocket_health_check():
            """Health check endpoint for WebSocket listener."""
            return {
                "status": "healthy",
                "active_connections": 0,  # Cannot track without connector storage
                "listener_type": "WebSocketListener",
            }

        return router

    async def _create_websocket_connector(
        self,
        *,
        system_id: str,
        websocket: WebSocket,
        origin_type: DeliveryOriginType,
        node: Any,
        authorization: Optional[AuthorizationContext] = None,
    ) -> WebSocketConnector:
        """
        Create a WebSocket connector for the given system.

        Args:
            system_id: The system ID for the connection
            websocket: The WebSocket connection
            origin_type: The origin type (downstream/peer)
            node: The node instance

        Returns:
            WebSocketConnector instance
        """
        connector_config = WebSocketConnectorConfig()

        # Check if node has create_origin_connector method (for Sentinel nodes)
        assert node and isinstance(node, RoutingNodeLike)
        connector = await node.create_origin_connector(
            origin_type=origin_type,
            system_id=system_id,
            connector_config=connector_config,
            websocket=websocket,
            authorization=authorization,
        )

        if not isinstance(connector, WebSocketConnector):
            raise RuntimeError(
                f"Invalid connector type. Expected: {WebSocketConnector}, actual: {type(connector)}"
            )

        return connector


# Test helper functions for backward compatibility
# Note: Since downstream connectors are only supported by RoutingNodeLike instances,
# these functions can't access the actual connectors without a reference to the node
_last_websocket_listener_instance: Optional[WebSocketListener] = None


def get_websocket_connector(system_id: str) -> Optional[WebSocketConnector]:
    """Get a WebSocket connector by system ID for testing/debugging purposes."""
    # Downstream connectors are managed by RoutingNodeLike instances
    # This function is kept for test compatibility but returns None
    return None
