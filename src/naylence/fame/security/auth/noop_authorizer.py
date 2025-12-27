from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from naylence.fame.core import AuthorizationContext, FameDeliveryContext, FameEnvelope
from naylence.fame.core.protocol.frames import NodeAttachFrame
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.auth.authorizer import Authorizer, RouteAuthorizationResult

if TYPE_CHECKING:
    from naylence.fame.security.auth.policy.authorization_policy_definition import RuleAction


class NoopAuthorizer(Authorizer):
    """
    A no-op NodeAttachAuthorizer that allows all attach requests unconditionally.
    """

    async def authenticate(
        self,
        credentials: str | bytes,
    ) -> Optional[AuthorizationContext]:
        # No authentication needed, just return an empty context
        return AuthorizationContext()

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Authorize access for any envelope unconditionally.

        Supports both new and legacy interfaces:
        - New: authorize(node, envelope, context: FameDeliveryContext)
        - Legacy: authorize(node, envelope, auth_context: AuthorizationContext)

        For NoopAuthorizer, always allows access by returning a valid authorization context.
        """
        # Backward compatibility: detect if context is actually an AuthorizationContext
        if context is None:
            # Return a basic authorization context
            return AuthorizationContext()
        elif hasattr(context, "authenticated"):
            # Legacy interface: context is an AuthorizationContext (duck typing check)
            return context  # type: ignore
        else:
            # New interface: context is a FameDeliveryContext
            # Extract existing authorization context from delivery context if available
            if context and context.security and context.security.authorization:
                return context.security.authorization

            # Return a basic authorization context
            return AuthorizationContext()

    async def authorize_route(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        action: RuleAction,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[RouteAuthorizationResult]:
        """
        Authorize routing action unconditionally.

        For NoopAuthorizer, always allows the routing action.
        """
        return RouteAuthorizationResult(authorized=True)

    # Legacy method for backward compatibility with NodeAttach frames
    async def validate_node_attach_request(
        self,
        node: NodeLike,
        frame: NodeAttachFrame,
        auth_context: Optional[AuthorizationContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Legacy method for NodeAttach frame validation.
        Always returns a valid context since this is a no-op authorizer.
        """
        return AuthorizationContext()
