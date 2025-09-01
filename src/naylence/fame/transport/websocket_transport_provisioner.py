from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

from pydantic import AnyWebsocketUrl

from naylence.fame.core import NodeHelloFrame
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant
from naylence.fame.transport.transport_provisioner import (
    TransportProvisioner,
    TransportProvisionerConfig,
    TransportProvisionerFactory,
    TransportProvisionResult,
)

if TYPE_CHECKING:
    from naylence.fame.placement.node_placement_strategy import PlacementDecision


class WebSocketTransportProvisionerConfig(TransportProvisionerConfig):
    type: str = "WebSocketTransportProvisioner"
    url: AnyWebsocketUrl


class WebSocketTransportProvisioner(TransportProvisioner):
    """
    Provides a static WebSocket endpoint to connect to a Fame router.
    Used for local or dev setups where all nodes use the same WebSocket listener.
    """

    TRANSPORT_TYPE_WEBSOCKET = "websocket"

    def __init__(
        self,
        url: str = "ws://localhost:8080/fame/ws/downstream",
        ttl_sec: int = 3600,
    ):
        self._url = url
        self._ttl = ttl_sec  # timedelta(seconds=ttl_sec)

    async def provision(
        self,
        decision: PlacementDecision,
        hello: NodeHelloFrame,
        full_metadata: Dict,
        attach_token: Optional[str] = None,
    ) -> TransportProvisionResult:
        if hello.supported_transports and self.TRANSPORT_TYPE_WEBSOCKET not in hello.supported_transports:
            raise ValueError(f"Unsupported transports: {hello.supported_transports}")

        # Create auth configuration if attach_token is provided
        auth_config = None
        if attach_token:
            # Import here to avoid circular import issues
            from naylence.fame.security.auth.static_token_provider_factory import (
                StaticTokenProviderConfig,
            )
            from naylence.fame.security.auth.websocket_subprotocol_auth_injection_strategy_factory import (
                WebSocketSubprotocolAuthInjectionConfig,
            )

            # Use WebSocket subprotocol auth for WebSocket connections
            auth_config = WebSocketSubprotocolAuthInjectionConfig(
                token_provider=StaticTokenProviderConfig(token=attach_token, type="StaticTokenProvider")
            )

        # Add system_id as query parameter to the URL
        # url_with_system_id = f"{self._url}"

        connection_grant = WebSocketConnectionGrant(
            purpose=GRANT_PURPOSE_NODE_ATTACH,
            url=self._url,
            auth=auth_config,
        )

        return TransportProvisionResult(
            connection_grant=connection_grant.model_dump(by_alias=True),
            cleanup_handle=None,  # nothing to clean up
        )

    async def deprovision(self, cleanup_handle: Optional[str]) -> None:
        # No-op for WebSocket (stateless)
        pass


class WebSocketTransportProvisionerFactory(TransportProvisionerFactory):
    async def create(
        self,
        config: Optional[WebSocketTransportProvisionerConfig | dict[str, Any]] = None,
        **kwargs,
    ) -> WebSocketTransportProvisioner:
        if not config:
            raise ValueError("Config not set")
        url = config["url"] if isinstance(config, dict) else str(config.url)
        return WebSocketTransportProvisioner(url=url)
