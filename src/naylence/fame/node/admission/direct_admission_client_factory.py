from __future__ import annotations

from typing import Any, Optional

from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)


class DirectNodeAdmissionConfig(AdmissionConfig):
    type: str = "DirectAdmissionClient"

    connector_directive: dict[str, Any]  # ConnectorConfig
    ttl_sec: int | None = None


class DirectAdmissionClientFactory(AdmissionClientFactory):
    async def create(
        self,
        config: Optional[DirectNodeAdmissionConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AdmissionClient:
        assert config

        if isinstance(config, dict):
            config = DirectNodeAdmissionConfig(**config)

        from naylence.fame.node.admission.direct_admission_client import (
            DirectAdmissionClient,
        )

        return DirectAdmissionClient(
            connector_directive=config.connector_directive,
            ttl_sec=config.ttl_sec,
        )
