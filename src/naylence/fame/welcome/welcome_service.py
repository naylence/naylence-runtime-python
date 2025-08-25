from __future__ import annotations

from typing import Optional, Protocol, TypeVar, runtime_checkable

from naylence.fame.core import (
    ExtensionManager,
    NodeHelloFrame,
    NodeWelcomeFrame,
    ResourceFactory,
    create_resource,
)
from naylence.fame.welcome.welcome_service_config import WelcomeServiceConfig


@runtime_checkable
class WelcomeService(Protocol):
    """
    Admission controller façade called by the bootstrap connector
    OR by a RoutingNode proxy.
    """

    async def handle_hello(self, hello: NodeHelloFrame) -> NodeWelcomeFrame: ...


C = TypeVar("C", bound=WelcomeServiceConfig)


class WelcomeServiceFactory(ResourceFactory[WelcomeService, C]):
    @staticmethod
    async def create_welcome_service(
        config: Optional[WelcomeServiceConfig] = None,
    ) -> WelcomeService:
        from naylence.fame.placement.node_placement_strategy import (
            NodePlacementStrategyFactory,
        )
        from naylence.fame.transport.transport_provisioner import (
            TransportProvisionerFactory,
        )

        ExtensionManager.lazy_init(group="naylence.WelcomeServiceFactory", base_type=WelcomeServiceFactory)
        ExtensionManager.lazy_init(
            group="naylence.NodePlacementStrategyFactory",
            base_type=NodePlacementStrategyFactory,
        )
        ExtensionManager.lazy_init(
            group="naylence.TransportProvisionerFactory",
            base_type=TransportProvisionerFactory,
        )

        fame_welcome_config = None
        if not config:
            from naylence.fame.config.config import ExtendedFameConfig, get_fame_config

            fame_config = get_fame_config()
            assert isinstance(fame_config, ExtendedFameConfig)
            fame_welcome_config = fame_config.welcome
        return await create_resource(WelcomeServiceFactory, config or fame_welcome_config)
