from __future__ import annotations

from typing import Any, Optional

from pydantic import ConfigDict

from naylence.fame.core import create_resource
from naylence.fame.placement.node_placement_strategy import (
    NodePlacementConfig,
)
from naylence.fame.security.auth.token_issuer_factory import (
    TokenIssuerConfig,
    TokenIssuerFactory,
)
from naylence.fame.transport.transport_provisioner import (
    TransportProvisionerConfig,
    TransportProvisionerFactory,
)
from naylence.fame.welcome.welcome_service import (
    WelcomeService,
    WelcomeServiceFactory,
)
from naylence.fame.welcome.welcome_service_config import WelcomeServiceConfig


class DefaultWelcomeServiceConfig(WelcomeServiceConfig):
    type: str = "DefaultWelcomeService"
    model_config = ConfigDict(extra="allow")
    placement: Optional[NodePlacementConfig] = None
    transport: Optional[TransportProvisionerConfig] = None
    token_issuer: Optional[TokenIssuerConfig] = None


class DefaultWelcomeServiceFactory(WelcomeServiceFactory):
    async def create(
        self,
        config: Optional[DefaultWelcomeServiceConfig] = None,
        **kwargs: dict[str, Any],
    ) -> WelcomeService:
        assert config

        from naylence.fame.placement.node_placement_strategy import (
            NodePlacementStrategyFactory,
        )
        from naylence.fame.welcome.default_welcome_service import DefaultWelcomeService

        placement_strategy = await create_resource(NodePlacementStrategyFactory, config.placement)
        transpot_provisioner = await create_resource(TransportProvisionerFactory, config.transport)
        token_issuer = await create_resource(TokenIssuerFactory, config.token_issuer)

        return DefaultWelcomeService(
            placement_strategy=placement_strategy,
            transport_provisioner=transpot_provisioner,
            token_issuer=token_issuer,
        )
