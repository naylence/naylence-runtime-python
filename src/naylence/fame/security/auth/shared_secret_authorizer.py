from __future__ import annotations

from typing import Optional

from naylence.fame.core import (
    AuthorizationContext,
    FameDeliveryContext,
    FameEnvelope,
    NodeAttachFrame,
)
from naylence.fame.node.node_context import FameNodeAuthorizationContext
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.credential import CredentialProvider


class SharedSecretAuthorizer(Authorizer):
    """
    A shared secret authorizer that validates tokens using a shared secret.
    """

    def __init__(self, credential_provider: CredentialProvider):
        self._credential_provider = credential_provider

    async def authenticate(
        self,
        credentials: str | bytes,
    ) -> Optional[AuthorizationContext]:
        """Validate shared secret credentials."""
        expected_secret = await self._credential_provider.get()
        if not expected_secret:
            raise ValueError("Shared secret not configured")

        # Extract token from credentials
        token = credentials
        if isinstance(credentials, bytes):
            token = credentials.decode("utf-8")

        # Strip "Bearer " prefix if present
        if isinstance(token, str) and token.lower().startswith("bearer "):
            token = token[7:]

        if not token:
            return None  # No token provided

        if token != expected_secret:
            return None  # Invalid token

        # Return basic authorization context for shared secret mode
        return AuthorizationContext(
            authenticated=True,
            principal="shared_secret_user",
            auth_method="shared_secret",
        )

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Authorize access based on the current authentication context.

        Supports both new and legacy interfaces:
        - New: authorize(node, envelope, context: FameDeliveryContext)
        - Legacy: authorize(node, envelope, auth_context: AuthorizationContext)

        For shared secret auth, if authenticated then authorized.
        """
        # Backward compatibility: detect if context is actually an AuthorizationContext
        auth_context: Optional[AuthorizationContext] = None

        if context is None:
            auth_context = None
        elif hasattr(context, "authenticated"):
            # Legacy interface: context is an AuthorizationContext (duck typing check)
            auth_context = context  # type: ignore
        else:
            # New interface: context is a FameDeliveryContext
            if context and context.security and context.security.authorization:
                auth_context = context.security.authorization

        if not auth_context or not auth_context.authenticated:
            return None

        # For shared secret auth, if authenticated then authorized
        return auth_context

    async def validate_node_attach_request(
        self,
        node: NodeLike,
        frame: NodeAttachFrame,
        auth_context: Optional[AuthorizationContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Validate node attach request using the already-authenticated context.
        No longer uses attach_token from frame - relies on wire-level auth.
        """
        if not auth_context or not auth_context.authenticated:
            return None  # Must be authenticated via wire-level auth first

        # The wire-level authentication already validated the credentials
        # Just create the node-specific authorization context
        return FameNodeAuthorizationContext(
            sub=frame.system_id,
            aud=node.id,
            instance_id=frame.instance_id,
            assigned_path=frame.assigned_path,
            accepted_capabilities=(list(frame.capabilities) if frame.capabilities else None),
            accepted_logicals=(list(frame.accepted_logicals) if frame.accepted_logicals else None),
        )
