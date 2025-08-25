from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from naylence.fame.core import NodeHelloFrame, NodeWelcomeFrame, generate_id
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.welcome.welcome_service import WelcomeService

if TYPE_CHECKING:
    from naylence.fame.placement.node_placement_strategy import (
        FameNodePlacementStrategy,
    )
    from naylence.fame.transport.transport_provisioner import (
        TransportProvisioner,
        TransportProvisionResult,
    )


class DefaultWelcomeService(WelcomeService):
    def __init__(
        self,
        placement_strategy: FameNodePlacementStrategy,
        transport_provisioner: TransportProvisioner,
        token_issuer: TokenIssuer,
        ttl_sec: int = 3600,
    ):
        self._placement_strategy = placement_strategy
        self._token_issuer = token_issuer
        self._transport_provisioner = transport_provisioner
        self._ttl = ttl_sec

    async def handle_hello(
        self,
        hello: NodeHelloFrame,
        # parent_physical_path: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> NodeWelcomeFrame:
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(seconds=self._ttl)
        full_metadata = dict(metadata or {})
        full_metadata.setdefault("instance_id", hello.instance_id)

        # 0 ─ ensure we have a system_id (server-assigned on first connect)
        system_id = hello.system_id or generate_id()

        hello = hello.model_copy(update={"system_id": system_id})

        # Validate logicals for DNS hostname compatibility
        from naylence.fame.util.logicals_util import validate_host_logicals

        if hello.logicals:
            paths_valid, path_error = validate_host_logicals(hello.logicals)
            if not paths_valid:
                raise Exception(f"Invalid logical format: {path_error}")

        placement_result = await self._placement_strategy.place(hello)

        if not placement_result.accept:
            raise Exception(placement_result.reason or "Node not accepted")

        assigned_path = placement_result.assigned_path
        accepted_capabilities = (
            placement_result.metadata.get("accepted_capabilities") if placement_result.metadata else None
        )
        accepted_logicals = (
            placement_result.metadata.get("accepted_logicals")
            if placement_result.metadata
            else hello.logicals
        )

        token = self._token_issuer.issue(
            claims={
                "aud": placement_result.parent_physical_path,
                "system_id": system_id,
                "parent_path": placement_result.parent_physical_path,
                "assigned_path": placement_result.assigned_path,
                "accepted_logicals": accepted_logicals,
                "instance_id": full_metadata.get("instance_id") or generate_id(),
            },
            # system_id=hello.system_id,
            # parent_path=placement_result.parent_physical_path,
            # assigned_path=placement_result.assigned_path,
            # accepted_logicals=accepted_logicals,
            # attach_expires_at=placement_result.expires_at,
            # instance_id=full_metadata.get("instance_id") or generate_id(),
        )

        transport_info: TransportProvisionResult = await self._transport_provisioner.provision(
            placement_result, hello, full_metadata, token
        )

        return NodeWelcomeFrame(
            system_id=system_id,
            target_system_id=placement_result.target_system_id,
            instance_id=hello.instance_id,
            assigned_path=assigned_path,
            accepted_capabilities=accepted_capabilities,
            accepted_logicals=accepted_logicals,
            rejected_logicals=None,  # Optional: enhance later
            parent_physical_path=placement_result.parent_physical_path,
            connector_directive=transport_info.directive,
            metadata=full_metadata,
            expires_at=expiry,
        )
