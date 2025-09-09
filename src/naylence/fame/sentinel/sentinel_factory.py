from typing import Any, Callable, Optional

from pydantic import Field

from naylence.fame.config.peer_config import PeerConfig
from naylence.fame.connector.transport_listener_factory import TransportListenerFactory
from naylence.fame.constants.ttl_constants import TTL_NEVER_EXPIRES
from naylence.fame.factory import ExtensionManager, create_default_resource, create_resource
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.node.admission.admission_client_factory import AdmissionClientFactory
from naylence.fame.node.factory_commons import make_common_opts
from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.node.node_like_factory import NodeLikeFactory
from naylence.fame.security.auth.authorizer_factory import AuthorizerConfig
from naylence.fame.sentinel.load_balancing.composite_load_balancing_strategy import (
    CompositeLoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy import (
    LoadBalancingStrategy,
)
from naylence.fame.sentinel.load_balancing.load_balancing_strategy_factory import (
    LoadBalancingStrategyConfig,
    LoadBalancingStrategyFactory,
)
from naylence.fame.sentinel.load_balancing.sticky_load_balancing_strategy import (
    StickyLoadBalancingStrategy,
)
from naylence.fame.sentinel.peer import Peer
from naylence.fame.sentinel.routing_policy import (
    RoutingPolicy,
    RoutingPolicyConfig,
    RoutingPolicyFactory,
)
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.sentinel.store.route_store import RouteEntry
from naylence.fame.stickiness.load_balancer_stickiness_manager import (
    LoadBalancerStickinessManager,
)
from naylence.fame.stickiness.load_balancer_stickiness_manager_factory import (
    LoadBalancerStickinessManagerConfig,
    LoadBalancerStickinessManagerFactory,
)
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class SentinelConfig(FameNodeConfig):
    """
    Adds the routing-specific knobs
    so that the routing-node factory can assume router semantics.
    """

    type: str = "Sentinel"

    transport: Optional[dict[str, Any]] = Field(
        default=None,
        description="Connector transport config",
    )

    routing_policy: Optional[RoutingPolicyConfig] = Field(
        default=None,
        description="Routing policy config",
    )

    load_balancing: Optional[LoadBalancingStrategyConfig] = Field(
        default=None,
        description="Load balancing strategy config",
    )

    stickiness: Optional[LoadBalancerStickinessManagerConfig] = Field(
        default=None,
        description="Session affinity configuration for automatic AFT token injection",
    )

    authorizer: Optional[AuthorizerConfig] = Field(
        default=None,
        description="Configuration for attach authorizer",
    )

    peers: Optional[list[PeerConfig]] = None

    max_attach_ttl_sec: Optional[int] = Field(
        default=None,
        description="Maximum time-to-live for node attachments",
    )


class SentinelFactory(NodeLikeFactory):
    async def create(
        self,
        config: Optional[SentinelConfig | dict[str, Any]] = None,
        **_: Any,
    ) -> NodeLike:
        if config is None:
            cfg = SentinelConfig(mode="prod")
        elif isinstance(config, dict):
            cfg = SentinelConfig(**config)
        else:
            cfg = config

        # --- common, non-routing bits ---
        opts = await make_common_opts(cfg)

        # --- routing-specific wiring ---
        ExtensionManager.lazy_init(
            group="naylence.LoadBalancingStrategyFactory",
            base_type=LoadBalancingStrategyFactory,
        )
        ExtensionManager.lazy_init(group="naylence.RoutingPolicyFactory", base_type=RoutingPolicyFactory)

        # Prepare event listeners list combining common ones with Sentinel-specific ones
        event_listeners = opts.pop("event_listeners", [])  # Remove from opts to avoid duplicate

        transport_listeners = opts.pop("transport_listeners", [])

        if len(transport_listeners) == 0:
            transport_listener = await create_default_resource(TransportListenerFactory)
            if transport_listener is not None:
                transport_listeners.append(transport_listener)
                event_listeners.append(transport_listener)

        storage_provider: StorageProvider = opts["storage_provider"]
        route_store = await storage_provider.get_kv_store(RouteEntry, namespace="__route_store")

        stickiness_manager: Optional[LoadBalancerStickinessManager] = None
        if cfg.stickiness:
            # Pass key_provider so default impl can build a verifier lazily
            stickiness_manager = (
                await LoadBalancerStickinessManagerFactory.create_load_balancer_stickiness_manager(
                    cfg=cfg.stickiness,
                    key_provider=opts["key_store"],
                )
            )
            if isinstance(stickiness_manager, NodeEventListener):
                event_listeners.append(stickiness_manager)

        load_balancing_strategy = await self._create_load_balancing_strategy(
            cfg, stickiness_manager=stickiness_manager
        )

        # Create routing policy with smart stickiness defaults
        routing_policy = await self._create_routing_policy(
            cfg,
            load_balancing_strategy=load_balancing_strategy,
        )

        if isinstance(routing_policy, NodeEventListener):
            event_listeners.append(routing_policy)

        sentinel = Sentinel(
            routing_policy=routing_policy,
            route_store=route_store,
            event_listeners=event_listeners,
            stickiness_manager=stickiness_manager,
            max_attach_ttl_sec=cfg.max_attach_ttl_sec,
            **opts,
        )

        def get_system_id():
            return sentinel.id

        sentinel._peers = await self._create_peers(get_system_id, cfg.peers)

        return sentinel

    async def _create_peers(
        self,
        get_system_id: Callable[[], str],
        peer_configs: Optional[list[PeerConfig]] = None,
    ) -> list[Peer]:
        if peer_configs is None:
            return []
        peers: list[Peer] = []
        for peer_config in peer_configs:
            admission_client = await create_resource(AdmissionClientFactory, peer_config.admission)
            if admission_client is None and peer_config.direct_url:
                from naylence.fame.node.admission.direct_admission_client import (
                    DirectAdmissionClient,
                )

                connection_grants = [
                    {
                        "type": "WebSocketConnectionGrant",
                        "purpose": GRANT_PURPOSE_NODE_ATTACH,
                        "url": peer_config.direct_url,
                        "auth": {
                            "type": "WebSocketSubprotocolAuth",
                            "token_provider": {"type": "NoneTokenProvider"},
                        },
                    }
                ]
                admission_client = DirectAdmissionClient(
                    connection_grants=connection_grants,
                    ttl_sec=TTL_NEVER_EXPIRES,
                )
            assert admission_client is not None, "Admission client must be created"

            peers.append(Peer(admission_client=admission_client))

        return peers

    async def _create_load_balancing_strategy(
        self,
        cfg: SentinelConfig,
        stickiness_manager: Optional[LoadBalancerStickinessManager] = None,
    ) -> LoadBalancingStrategy:
        load_balancing_strategy: Optional[LoadBalancingStrategy]
        if cfg.load_balancing is not None:
            # Create load balancing strategy with provided config
            load_balancing_strategy = await create_resource(
                LoadBalancingStrategyFactory,
                cfg.load_balancing,
                stickiness_manager=stickiness_manager,
            )
        else:
            load_balancing_strategy = await LoadBalancingStrategyFactory.create_load_balancing_strategy()

        assert load_balancing_strategy is not None, "Load balancing strategy must be created"
        if cfg.stickiness and stickiness_manager:
            load_balancing_strategy = CompositeLoadBalancingStrategy(
                strategies=[
                    StickyLoadBalancingStrategy(stickiness_manager),
                    load_balancing_strategy,
                ]
            )

        return load_balancing_strategy

    async def _create_routing_policy(
        self, cfg: SentinelConfig, load_balancing_strategy: LoadBalancingStrategy
    ) -> RoutingPolicy:
        """Create routing policy with smart stickiness defaults."""

        if cfg.routing_policy is not None:
            # If a routing policy is explicitly provided, use it
            return await create_resource(
                RoutingPolicyFactory,
                cfg.routing_policy,
                load_balancing_strategy=load_balancing_strategy,
            )

        return await RoutingPolicyFactory.create_routing_policy(
            load_balancing_strategy=load_balancing_strategy
        )
