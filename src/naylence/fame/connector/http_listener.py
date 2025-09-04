from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Optional

from fastapi import APIRouter, HTTPException, Request

from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.connector.transport_listener import TransportListener
from naylence.fame.core import (
    AuthorizationContext,
    DeliveryOriginType,
    FameChannelMessage,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    NodeAttachFrame,
    SecurityContext,
)
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.no_auth_injection_strategy_factory import NoAuthInjectionStrategyConfig
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.connector.http_server import HttpServer
    from naylence.fame.node.node_like import NodeLike


logger = getLogger(__name__)


class HttpListener(TransportListener, NodeEventListener):
    """
    HTTP listener that provides ingress endpoints for HTTP stateless connectors.

    This listener creates a single HTTP server per node that handles:
    - Upstream ingress (child → parent)
    - Downstream ingress (parent → child)
    - Health checks
    - Connector registration/management
    """

    def __init__(
        self,
        *,
        http_server: HttpServer,
        authorizer: Optional[Authorizer] = None,
        **kwargs,
    ):
        global _last_http_listener_instance
        self._http_server = http_server
        self._authorizer = authorizer  # Per-listener authorizer
        self._public_url: Optional[str] = None  # Set from node.public_url in on_node_initialized
        self._router_registered = False
        self._node: Optional[NodeLike] = None
        # Register this instance for test helper functions
        _last_http_listener_instance = self

    # ── NodeEventListener interface ─────────────────────────────────────────

    async def on_node_initialized(self, node: NodeLike) -> None:
        """Register routes with the HTTP server when node is initialized."""
        if self._router_registered:
            return

        self._node = node
        # Get public_url from node
        self._public_url = node.public_url

        logger.debug("registering_http_routes", class_name=self.__class__.__name__)

        # Create and register the router
        router = await self.create_router()
        self._http_server.include_router(router)
        self._router_registered = True

        logger.debug("http_routes_registered", base_url=self._http_server.actual_base_url)

    async def on_node_stopped(self, node: NodeLike) -> None:
        """Clear all connectors when node stops."""
        # Connectors are managed by the RoutingNodeLike implementation
        self._router_registered = False

        # Release the HTTP server reference so it can be stopped if no longer needed
        if self._http_server:
            from naylence.fame.connector.default_http_server import DefaultHttpServer

            # If this is a DefaultHttpServer, release the reference
            if isinstance(self._http_server, DefaultHttpServer):
                await DefaultHttpServer.release(host=self._http_server.host, port=self._http_server.port)

    async def on_node_started(self, node: NodeLike) -> None:
        """Node has started - no special action needed for HTTP listener."""
        pass

    # ── TransportListener interface ──────────────────────────────────────────

    async def start(self) -> None:
        """Start the transport listener (HTTP server managed externally)."""
        # HTTP server lifecycle is managed externally
        pass

    async def stop(self) -> None:
        """Stop the transport listener (HTTP server managed externally)."""
        # For HTTP listeners, we need to ensure any pending connections are closed
        # The actual HTTP server lifecycle is managed externally but we can help
        # with cleanup of any resources we might be holding

        # If we have connectors that need cleanup, this would be the place
        # Currently connectors are managed by RoutingNodeLike, so no action needed
        logger.debug("http_listener_stopped")

    def as_callback_grant(self) -> Optional[dict[str, Any]]:
        """Return connector configuration for reverse connections."""
        if not self.base_url:
            return None

        # Determine auth configuration for reverse connections
        auth_config = NoAuthInjectionStrategyConfig()

        # Check if the node has a security manager with reverse authorization capability
        if self._node and self._node.security_manager:
            security_manager = self._node.security_manager
            if security_manager.authorizer:
                authorizer = security_manager.authorizer
                # Check if authorizer supports reverse authorization
                if hasattr(authorizer, "create_reverse_authorization_config"):
                    try:
                        reverse_auth_config = authorizer.create_reverse_authorization_config(self._node)
                        if reverse_auth_config:
                            # Use the auth config directly from the authorizer
                            auth_config = reverse_auth_config
                    except Exception as e:
                        # Log warning but fall back to NoAuth
                        logger.warning(
                            "failed_to_create_reverse_auth_for_connector",
                            error=str(e),
                            node_id=getattr(self._node, "id", "unknown"),
                        )

        connector = HttpConnectionGrant(
            purpose=GRANT_PURPOSE_NODE_ATTACH,
            url=f"{self.base_url}{self.upstream_endpoint}",
            auth=auth_config,
        )

        return connector.model_dump(by_alias=True)

    # ── Public API ───────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Check if the HTTP server is running."""
        return self._http_server.is_running

    @property
    def base_url(self) -> Optional[str]:
        """Get the base URL for this HTTP listener."""
        # Use public URL from node config if available, otherwise fall back to actual server URL
        return self._public_url or self._http_server.actual_base_url

    @property
    def ingress_prefix(self) -> str:
        """Get the ingress route prefix for this listener."""
        return "/fame/v1/ingress"

    @property
    def upstream_endpoint(self) -> str:
        """Get the upstream endpoint path."""
        return f"{self.ingress_prefix}/upstream"

    @property
    def http_server(self) -> HttpServer:
        """Get the injected HTTP server."""
        return self._http_server

    # ── HTTP Router Creation ─────────────────────────────────────────────────

    async def create_router(self) -> APIRouter:
        """Create the FastAPI router for HTTP ingress endpoints."""
        router = APIRouter(prefix=self.ingress_prefix)

        @router.post("/upstream", status_code=202)
        async def upstream_ingress(request: Request):
            """
            Handle upstream ingress (child → parent).

            This endpoint handles frames from child nodes to the parent.
            For upstream, we typically expect an existing connector since
            the child initiates the connection first.
            """
            assert self._node
            try:
                auth_result = None
                # Verify the authorization token
                auth_header = request.headers.get("authorization", "")

                # ① Perform authorization check
                authorizer = self._authorizer
                if not authorizer and self._node.security_manager:
                    # Fallback to node security manager authorizer
                    authorizer = self._node.security_manager.authorizer

                if authorizer:
                    try:
                        # First phase: authentication (token validation)
                        auth_result = await authorizer.authenticate(
                            auth_header
                        )  # self._node.physical_path, auth_header)

                        if auth_result is None:
                            logger.warning(
                                "upstream_ingress_authentication_failed",
                                reason="Authentication failed",
                                authorizer_type=type(authorizer).__name__,
                            )
                            raise HTTPException(401, "Authentication failed")

                        logger.debug(
                            "http_upstream_authentication_success",
                            authorizer_type=type(authorizer).__name__,
                        )
                    except HTTPException:
                        raise
                    except Exception as auth_error:
                        logger.error(
                            "http_upstream_authorization_error",
                            error=str(auth_error),
                            authorizer_type=type(authorizer).__name__,
                            exc_info=True,
                        )
                        raise HTTPException(500, f"Authorization error: {str(auth_error)}")
                else:
                    logger.debug(
                        "http_upstream_no_authorization",
                        message="No authorizer configured - allowing request",
                    )

                # Read the request body (Fame envelope JSON)
                body = await request.body()
                if not body:
                    raise HTTPException(400, "Empty request body")

                # Parse the Fame envelope - upstream should also use structured data
                try:
                    envelope = FameEnvelope.model_validate_json(body.decode("utf-8"))
                except Exception as parse_error:
                    logger.warning(
                        "upstream_invalid_request_body",
                        error=str(parse_error),
                        body_preview=body[:100] if len(body) > 100 else body,
                    )
                    raise HTTPException(400, "Invalid request body - expected FameEnvelope JSON")

                # Use the NodeLike.upstream_connector property
                upstream_connector = self._node.upstream_connector
                if not upstream_connector:
                    raise HTTPException(503, "No upstream connector available")

                # If we have a valid connector, we can process the request
                if not isinstance(upstream_connector, HttpStatelessConnector):
                    raise HTTPException(503, "Upstream connector is not a HttpStatelessConnector")

                # Push envelope wrapped in FameChannelMessage to the connector's receive queue
                try:
                    await upstream_connector.push_to_receive(
                        FameChannelMessage(
                            envelope=envelope,
                            context=FameDeliveryContext(
                                origin_type=DeliveryOriginType.UPSTREAM,
                                from_connector=upstream_connector,
                                from_system_id=None,  # Will be determined from auth context or envelope
                                security=SecurityContext(authorization=auth_result),
                            ),
                        )
                    )
                except asyncio.QueueFull:
                    raise HTTPException(429, "receiver busy")

                # Return flow control information
                return {"status": "message_received"}

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error in upstream handler: {e}", exc_info=True)
                raise HTTPException(500, f"Internal server error: {e}")

        @router.post("/downstream/{child_id}", status_code=202)
        async def downstream_ingress(child_id: str, request: Request):
            """
            Handle downstream ingress (parent → child).

            This endpoint serves two purposes:
            1. Initial NodeAttach frame processing (handshake to create connector)
            2. Subsequent frame delivery to established connector
            """
            assert self._node
            try:
                auth_result = None
                # Verify the authorization token with expected audience
                auth_header = request.headers.get("authorization", "")

                # ① Perform authorization check
                authorizer = self._authorizer
                if not authorizer and self._node.security_manager:
                    # Fallback to node security manager authorizer
                    authorizer = self._node.security_manager.authorizer

                if authorizer:
                    try:
                        # First phase: authentication (token validation)
                        auth_result = await authorizer.authenticate(auth_header)

                        if auth_result is None:
                            logger.warning(
                                "http_downstream_authorization_failed",
                                child_id=child_id,
                                reason="Authentication failed",
                                authorizer_type=type(authorizer).__name__,
                            )
                            raise HTTPException(401, "Authentication failed")

                        logger.debug(
                            "http_downstream_authorization_success",
                            child_id=child_id,
                            authorizer_type=type(authorizer).__name__,
                        )
                    except HTTPException:
                        raise
                    except Exception as auth_error:
                        logger.error(
                            "http_downstream_authorization_error",
                            child_id=child_id,
                            error=str(auth_error),
                            authorizer_type=type(authorizer).__name__,
                            exc_info=True,
                        )
                        raise HTTPException(500, f"Authorization error: {str(auth_error)}")
                else:
                    logger.debug(
                        "http_downstream_ingress_no_authorization",
                        child_id=child_id,
                        message="No authorizer configured - allowing request",
                    )

                # Read the request body (binary Fame envelope)
                body = await request.body()
                if not body:
                    raise HTTPException(400, "Empty request body")

                # Parse the Fame envelope to determine the frame type
                try:
                    # Try to parse as JSON first (most common case)
                    envelope = FameEnvelope.model_validate_json(body.decode("utf-8"))
                except Exception:
                    # If JSON parsing fails, it might be binary data for an existing connector
                    envelope = None

                # Check if this is a NodeAttach frame (handshake)
                if envelope and isinstance(envelope.frame, NodeAttachFrame):
                    attach_frame = envelope.frame
                    logger.debug(
                        "processing_node_attach",
                        child=child_id,
                        system_id=attach_frame.system_id,
                    )

                    # Verify the child_id matches the frame's system_id
                    if child_id != attach_frame.system_id:
                        logger.warning(
                            "child_id_mismatch",
                            child=child_id,
                            frame=attach_frame.system_id,
                        )
                        raise HTTPException(400, "Child ID mismatch")

                    # Create the origin connector through proper attach handling with error handling
                    try:
                        conn = await self._handle_node_attach_frame(
                            child_id=child_id,
                            attach_frame=attach_frame,
                            envelope=envelope,
                            node=self._node,
                            authorization=auth_result,
                        )

                        try:
                            await conn.push_to_receive(
                                FameChannelMessage(
                                    envelope=envelope,
                                    context=FameDeliveryContext(
                                        origin_type=DeliveryOriginType.DOWNSTREAM,
                                        from_connector=conn,
                                        from_system_id=child_id,
                                        security=SecurityContext(authorization=auth_result),
                                    ),
                                )
                            )
                        except asyncio.QueueFull:
                            raise HTTPException(429, "receiver busy")

                        # The NodeAttachFrameHandler will process this frame and send the response
                        # For now, we return a simple acknowledgment
                        return {"status": "attach_in_progress"}

                    except Exception as e:
                        # Log the attachment error and provide immediate feedback
                        logger.error(
                            "node_attach_failed",
                            child=child_id,
                            error=str(e),
                            action="rejecting_http_request",
                        )

                        # Return immediate error response instead of letting client timeout
                        error_message = f"Node attachment failed: {str(e)}"
                        if "No suitable connector found" in str(e):
                            error_message = "No compatible connector configuration available"
                        elif "ConnectError" in str(e) or "connection" in str(e).lower():
                            error_message = "Cannot establish outbound connection for attachment"
                        elif "Invalid connector" in str(e):
                            error_message = "Connector configuration error"
                        elif "certificate" in str(e).lower():
                            error_message = "Certificate validation failed"

                        raise HTTPException(400, error_message)

                elif envelope:
                    # This is a regular frame for an existing connector (FameEnvelope but not NodeAttach)
                    conn = self._get_existing_connector(child_id)
                    if not conn:
                        # No connector exists - child must attach first
                        logger.warning(f"No connector for {child_id} - NodeAttach required first")
                        raise HTTPException(400, "No established connection - NodeAttach required")

                    # Push envelope wrapped in FameChannelMessage to the connector's receive queue
                    try:
                        await conn.push_to_receive(
                            FameChannelMessage(
                                envelope=envelope,
                                context=FameDeliveryContext(
                                    origin_type=DeliveryOriginType.DOWNSTREAM,
                                    from_connector=conn,
                                    from_system_id=child_id,
                                    security=SecurityContext(authorization=auth_result),
                                ),
                            )
                        )
                    except asyncio.QueueFull:
                        raise HTTPException(429, "receiver busy")

                    # Return flow control information
                    return {"status": "message_received"}

                else:
                    # Could not parse as FameEnvelope - this is invalid for HTTP downstream
                    logger.warning(
                        "invalid_request_body",
                        child=child_id,
                        body_preview=body[:100] if len(body) > 100 else body,
                    )
                    raise HTTPException(400, "Invalid request body - expected FameEnvelope JSON")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error in downstream handler: {e}", exc_info=True)
                raise HTTPException(500, f"Internal server error: {e}")

        @router.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                # "connectors": len(_connectors),
                # "listener_url": self.base_url,
            }

        return router

    async def _handle_node_attach_frame(
        self,
        *,
        child_id: str,
        attach_frame: NodeAttachFrame,
        envelope: FameEnvelope,
        node: Any,
        authorization: Optional[AuthorizationContext] = None,
    ) -> FameConnector:  # Return the actual connector type selected by policy
        """
        Handle a NodeAttach frame by creating a connector for the child.

        Args:
            child_id: The child system ID from URL
            attach_frame: The parsed NodeAttach frame
            envelope: The complete Fame envelope
            node: The node instance

        Returns:
            FameConnector instance for the child (type determined by selection policy)
        """
        from naylence.fame.connector.grant_selection_policy import (
            GrantSelectionContext,
            default_grant_selection_policy,
        )

        # Use the connector selection policy to choose the appropriate connector
        # This addresses the TODOs by providing a pluggable policy system that considers:
        # - Client's supported inbound connectors
        # - Node preferences
        # - Inbound connector type that received the request
        # - Fallback strategies

        context = GrantSelectionContext(
            child_id=child_id,
            attach_frame=attach_frame,
            callback_grant_type="HttpConnectionGrant",  # This is an HTTP listener
            node=node,
        )

        # Use the policy to select the best connector configuration
        selection_result = default_grant_selection_policy.select_callback_grant(context)

        assert selection_result is not None, "No suitable connector found"

        # Log the selection for debugging
        if selection_result.fallback_used:
            logger.warning(
                "using_fallback_connector",
                child=child_id,
                reason=selection_result.selection_reason,
                connector_type=selection_result.grant.type,
            )
        else:
            logger.debug(
                "connector_selected",
                child=child_id,
                reason=selection_result.selection_reason,
                connector_type=selection_result.grant.type,
            )

        grant = selection_result.grant

        connector_config = grant.to_connector_config()

        # Check if node has create_origin_connector method (for Sentinel nodes)
        assert node and isinstance(node, RoutingNodeLike), "Node must be a RoutingNodeLike instance"
        connector = await node.create_origin_connector(
            origin_type=DeliveryOriginType.DOWNSTREAM,  # HTTP child connections are downstream
            system_id=child_id,
            connector_config=connector_config,
            authorization=authorization,
        )

        # Connector will be managed by the RoutingNodeLike implementation (route manager)
        logger.debug(
            "created_http_connector",
            child=child_id,
            connector_type=type(connector).__name__,
            config_details=str(grant),
        )

        return connector

    def _get_existing_connector(self, child_id: str) -> Optional[FameConnector]:
        """Get an existing connector for a child."""
        # Only RoutingNodeLike instances support downstream connectors
        from naylence.fame.node.routing_node_like import RoutingNodeLike

        if isinstance(self._node, RoutingNodeLike):
            connector = self._node._downstream_connector(child_id)
            if connector:  # Accept any connector type selected by policy
                return connector

        return None


# Test helper functions for backward compatibility
# Note: Since downstream connectors are only supported by RoutingNodeLike instances,
# these functions can't access the actual connectors without a reference to the node
_last_http_listener_instance: Optional[HttpListener] = None


def get_connector(system_id: str) -> Optional[HttpStatelessConnector]:
    """Get a connector by system ID for testing/debugging purposes."""
    # In production, connectors are managed by RoutingNodeLike instances
    if _last_http_listener_instance and _last_http_listener_instance._node:
        from naylence.fame.node.routing_node_like import RoutingNodeLike

        node = _last_http_listener_instance._node
        if isinstance(node, RoutingNodeLike):
            connector = node._downstream_connector(system_id)
            if isinstance(connector, HttpStatelessConnector):
                return connector

    return None
