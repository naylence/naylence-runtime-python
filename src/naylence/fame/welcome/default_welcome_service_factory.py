from __future__ import annotations

from typing import Any, Optional

from pydantic import ConfigDict

from naylence.fame.placement.node_placement_strategy import (
    NodePlacementConfig,
)
from naylence.fame.security.auth.authorizer_factory import AuthorizerConfig, AuthorizerFactory
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
)
from naylence.fame.welcome.welcome_service_factory import WelcomeServiceConfig, WelcomeServiceFactory


class DefaultWelcomeServiceConfig(WelcomeServiceConfig):
    type: str = "DefaultWelcomeService"

    placement: Optional[NodePlacementConfig] = None
    transport: Optional[TransportProvisionerConfig] = None
    token_issuer: Optional[TokenIssuerConfig] = None
    authorizer: Optional[AuthorizerConfig] = None

    model_config = ConfigDict(extra="allow")


class DefaultWelcomeServiceFactory(WelcomeServiceFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultWelcomeServiceConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> WelcomeService:
        from naylence.fame.placement.node_placement_strategy import (
            NodePlacementStrategyFactory,
        )
        from naylence.fame.welcome.default_welcome_service import DefaultWelcomeService

        if isinstance(config, dict):
            config = DefaultWelcomeServiceConfig(**config)

        placement_strategy = await NodePlacementStrategyFactory.create_node_placement_strategy(
            config.placement if config else None, **kwargs
        )

        transport_provider = await TransportProvisionerFactory.create_transport_provisioner(
            config.transport if config else None, **kwargs
        )

        token_issuer = await TokenIssuerFactory.create_token_issuer(
            config.token_issuer if config else None, **kwargs
        )

        authorizer = None
        if config and config.authorizer:
            authorizer = await AuthorizerFactory.create_authorizer(config.authorizer)

        return DefaultWelcomeService(
            placement_strategy=placement_strategy,
            transport_provisioner=transport_provider,
            token_issuer=token_issuer,
            authorizer=authorizer,
        )
