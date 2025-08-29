from __future__ import annotations

from typing import Any, List, Optional

from pydantic import Field, HttpUrl

from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)
from naylence.fame.security.auth.auth_config import ConnectorAuth, NoAuth
from naylence.fame.security.auth.auth_injection_strategy_factory import (
    create_auth_strategy,
)


class WelcomeServiceClientConfig(AdmissionConfig):
    type: str = "WelcomeServiceClient"
    url: HttpUrl
    supported_transports: List[str] = Field(..., description="Allowed transports")
    auth: ConnectorAuth = Field(default_factory=NoAuth, description="Authentication configuration")


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
        auth_strategy = await create_auth_strategy(config.auth)

        # Create client
        client = WelcomeServiceClient(
            url=str(config.url),
            supported_transports=config.supported_transports,
            auth_strategy=auth_strategy,
        )

        # Apply authentication strategy (treat client as Any to bypass type checking)
        await auth_strategy.apply(client)  # type: ignore

        return client
