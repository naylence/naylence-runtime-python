from __future__ import annotations

from typing import Any, List, Optional

from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)


class DirectNodeAdmissionConfig(AdmissionConfig):
    type: str = "DirectAdmissionClient"

    connection_grants: List[dict[str, Any]]
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

        preprocessed_grants = []

        for grant in config.connection_grants:
            # Round-trip the grant to evaluate expressions. TODO: make this more efficient
            evaluated_grant = ConnectorFactory.evaluate_grant(grant)
            preprocessed_grants.append(evaluated_grant.model_dump(by_alias=True))

        # Extract node_identity_policy from kwargs if provided
        node_identity_policy = kwargs.get("node_identity_policy")

        return DirectAdmissionClient(
            connection_grants=preprocessed_grants,
            ttl_sec=config.ttl_sec,
            node_identity_policy=node_identity_policy,
        )
