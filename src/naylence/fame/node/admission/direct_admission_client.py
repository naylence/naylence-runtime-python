from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, List, Optional

from naylence.fame.constants.ttl_constants import (
    DEFAULT_DIRECT_ADMISSION_TTL_SEC,
    TTL_NEVER_EXPIRES,
)
from naylence.fame.core import FameEnvelopeWith, NodeWelcomeFrame, generate_id
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.util import logging
from naylence.fame.util.ttl_validation import validate_ttl_sec

if TYPE_CHECKING:
    from naylence.fame.node.node_identity_policy import NodeIdentityPolicy

logger = logging.getLogger(__name__)


class DirectAdmissionClient(AdmissionClient):
    """
    Direct admission client.

    * Never talks to a Welcome-service.
    * Generates attach params entirely from config.
    * Uses the provided connection grants as-is (including any auth configuration).
    """

    def __init__(
        self,
        connection_grants: List[dict[str, Any]],
        ttl_sec: int | None = TTL_NEVER_EXPIRES,  # 0 = never expires
        node_identity_policy: Optional[NodeIdentityPolicy] = None,
    ) -> None:
        self._connection_grants = connection_grants
        # Validate TTL but allow TTL_NEVER_EXPIRES (0) and None
        if ttl_sec is not None and ttl_sec != TTL_NEVER_EXPIRES:
            ttl_sec = validate_ttl_sec(
                ttl_sec,
                min_ttl_sec=60,  # At least 1 minute for admission
                max_ttl_sec=86400 * 7,  # Max 7 days
                allow_never_expires=True,
                context="Direct admission TTL",
            )  # pyright: ignore[reportAssignmentType]
        self._ttl_sec = ttl_sec
        self._node_identity_policy = node_identity_policy

    async def hello(
        self,
        system_id: str,
        instance_id: str,
        requested_logicals: Optional[List[str]] = None,
    ) -> FameEnvelopeWith[NodeWelcomeFrame]:
        logger.debug("creating welcome frame")

        now = datetime.now(timezone.utc)

        # Determine the expiration time based on client TTL
        if self._ttl_sec and self._ttl_sec != TTL_NEVER_EXPIRES:
            expires_at = now + timedelta(seconds=self._ttl_sec)
        else:
            # Default to 24 hours for direct admission when TTL is 0 (never expires) or None
            # Direct admission doesn't use a welcome service, so longer default is appropriate
            expires_at = now + timedelta(seconds=DEFAULT_DIRECT_ADMISSION_TTL_SEC)

        if not system_id:
            system_id = generate_id(mode="fingerprint")

        # Resolve effective system ID using identity policy if available
        effective_system_id = system_id
        if self._node_identity_policy:
            from naylence.fame.node.node_identity_policy import (
                NodeIdentityPolicyContext,
            )

            effective_system_id = (
                await self._node_identity_policy.resolve_admission_node_id(
                    NodeIdentityPolicyContext(
                        current_node_id=system_id,
                        identities=[],
                        grants=self._connection_grants,
                    )
                )
            )

        envelope = FameEnvelopeWith(
            frame=NodeWelcomeFrame(
                system_id=effective_system_id,
                instance_id=instance_id,
                accepted_logicals=requested_logicals or ["*"],  # TODO get rid of the *
                expires_at=expires_at,
                connection_grants=self._connection_grants,
            )
        )

        return envelope

    async def close(self) -> None:
        pass
