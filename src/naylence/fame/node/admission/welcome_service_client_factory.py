from __future__ import annotations

from typing import Any, List, Optional

from pydantic import Field, HttpUrl

from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)
from naylence.fame.security.auth.no_auth_injection_strategy_factory import NoAuthInjectionStrategyConfig


class WelcomeServiceClientConfig(AdmissionConfig):
    type: str = "WelcomeServiceClient"
    url: HttpUrl
    supported_transports: List[str] = Field(..., description="Allowed transports")
    auth: AuthInjectionStrategyConfig = Field(
        default_factory=NoAuthInjectionStrategyConfig, description="Authentication configuration"
    )
    is_root: bool = Field(default=False, description="Whether the client serves a root node")


class WelcomeServiceClientFactory(AdmissionClientFactory):
    async def create(
        self,
        config: Optional[WelcomeServiceClientConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AdmissionClient:
        if not config:
            raise RuntimeError("Missing WelcomeServiceClientConfig config for admission service client")
        if isinstance(config, dict):
            config = WelcomeServiceClientConfig.model_validate(config)

        from naylence.fame.node.admission.welcome_service_client import (
            WelcomeServiceClient,
        )

        # Create auth strategy
        auth_strategy = await AuthInjectionStrategyFactory.create_auth_strategy(config.auth)

        # Create client
        client = WelcomeServiceClient(
            has_upstream=config.is_root is False,
            url=str(config.url),
            supported_transports=config.supported_transports,
            auth_strategy=auth_strategy,
        )

        # Apply authentication strategy (treat client as Any to bypass type checking)
        await auth_strategy.apply(client)  # type: ignore

        return client
