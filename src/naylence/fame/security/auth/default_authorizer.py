from __future__ import annotations

from typing import Optional

from naylence.fame.core import (
    AuthorizationContext,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    NodeAttachFrame,
)
from naylence.fame.node.node_context import FameNodeAuthorizationContext
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_provider import TokenVerifierProvider
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultAuthorizer(NodeEventListener, Authorizer, TokenVerifierProvider):
    def __init__(self, token_verifier: Optional[TokenVerifier] = None):
        super().__init__()
        self._token_verifier = token_verifier
        self._node: NodeLike | None = None

    @property
    def token_verifier(self) -> TokenVerifier:
        """Get the token verifier used by this authorizer."""
        if self._token_verifier is None:
            raise RuntimeError("Token verifier is not initialized")
        return self._token_verifier

    async def on_node_started(self, node: NodeLike) -> None:
        self._node = node

    async def authenticate(
        self,
        credentials: str | bytes,
    ) -> Optional[AuthorizationContext]:
        """Authenticate using JWT token with custom Fame claims."""
        # Extract token from credentials
        token = credentials
        if isinstance(credentials, bytes):
            token = credentials.decode("utf-8")

        # Strip "Bearer " prefix if present
        if isinstance(token, str) and token.lower().startswith("bearer "):
            token = token[7:]

        if not token:
            return None

        if not self._token_verifier:
            raise RuntimeError("DefaultAuthorizer is not initialized properly, missing token_verifier")

        try:
            raw_claims = await self._token_verifier.verify(
                str(token),
                expected_audience=self._node.physical_path if self._node else None,
            )

            # Create authorization context with Fame-specific claims
            return AuthorizationContext(
                authenticated=True,
                principal=raw_claims.get("sub"),
                claims=raw_claims,
                auth_method="jwt_fame_claims",
            )
        except Exception as e:
            logger.warning("token_verification_failed", exc_info=e)
            return None

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Authorize the envelope delivery based on the provided context.
        """

        if context and context.security and context.security.authorization:
            auth_context = context.security.authorization
        else:
            return None

        if auth_context.authorized is True:
            return auth_context

        # For node attach requests from non-local origins, perform detailed validation
        if (
            isinstance(envelope.frame, NodeAttachFrame)
            and context
            and context.origin_type != DeliveryOriginType.LOCAL
        ):
            frame = envelope.frame

            # Convert to FameNodeAuthorizationContext if it's a basic AuthorizationContext
            if not isinstance(auth_context, FameNodeAuthorizationContext):
                # Can't validate node-specific fields with basic AuthorizationContext
                # Just return it as is - the authorization was already done
                return auth_context

            # Validate node attach specific claims
            if auth_context.sub != frame.system_id:
                raise ValueError("Token sub doesn't match system id")

            if auth_context.instance_id != frame.instance_id:
                raise ValueError("Token instance ID mismatch")

            # Validate that the token audience matches the target node
            if auth_context.aud != node.id:
                raise ValueError("Token audience doesn't match target node")

            if frame.assigned_path and frame.assigned_path != auth_context.assigned_path:
                raise ValueError("Assigned path is not authorized by token")

            # Optional: Logicals
            if frame.accepted_logicals:
                token_paths = set(auth_context.accepted_logicals or [])
                if not set(frame.accepted_logicals).issubset(token_paths):
                    raise ValueError("Logicals not authorized by token")

            # Optional: Capabilities
            if frame.capabilities:
                token_caps = set(auth_context.accepted_capabilities or [])
                if not set(frame.capabilities).issubset(token_caps):
                    raise ValueError("Capabilities not authorized by token")

        # For DefaultAuthorizer, if authenticated then authorized
        return auth_context
