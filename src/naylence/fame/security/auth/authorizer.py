from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from naylence.fame.core import AuthorizationContext, FameDeliveryContext, FameEnvelope
from naylence.fame.node.node_like import NodeLike

if TYPE_CHECKING:
    from naylence.fame.security.auth.policy.authorization_policy_definition import RuleAction


class RouteAuthorizationResult(BaseModel):
    """
    Route authorization result returned by authorize_route.

    Attributes:
        authorized: Whether the route action is authorized.
        auth_context: The authorization context (if authorized).
        denial_reason: Reason for denial (for internal logging only, not for on-wire disclosure).
        matched_rule: Matched rule ID (for logging/audit).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    authorized: bool
    auth_context: Optional[AuthorizationContext] = Field(default=None)
    denial_reason: Optional[str] = Field(default=None)
    matched_rule: Optional[str] = Field(default=None)


@runtime_checkable
class Authorizer(Protocol):
    """
    Generic authorization interface supporting multi-phase authentication/authorization.

    This protocol supports both:
    1. Early authentication (token validation from network layer)
    2. Later authorization (envelope-level permission checking including node attach requests)

    The authorize method now accepts the full FameDeliveryContext to enable comprehensive
    authorization decisions based on the complete context including origin, security, and
    authorization information.
    """

    async def authenticate(
        self,
        credentials: str | bytes,
    ) -> Optional[AuthorizationContext]: ...

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]: ...

    async def authorize_route(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        action: RuleAction,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[RouteAuthorizationResult]:
        """
        Authorizes a routing action after the routing decision has been made.

        This method is called with the explicitly mapped action token from the
        routing decision (ForwardUpstream, ForwardDownstream, ForwardPeer,
        DeliverLocal). It does NOT receive RoutingAction objects to avoid
        coupling authorization logic to routing execution behavior.

        Args:
            node: The node handling the request
            envelope: The FAME envelope being routed
            action: The authorization action token (route-oriented)
            context: Optional delivery context

        Returns:
            RouteAuthorizationResult if implemented, or None to allow
        """
        ...

    def create_reverse_authorization_config(self, node: NodeLike) -> Optional[Any]:
        """
        Create authorization configuration for reverse connections (parent -> child).

        This method allows the authorizer to generate credentials/tokens that can be
        used by a parent node when connecting back to this child node. The returned
        configuration should be a Auth instance suitable for connector configurations.

        Args:
            node: The node that will receive the reverse connection

        Returns:
            Dict containing authorization configuration, or None if reverse auth not supported.
            Authorizers that have a corresponding TokenIssuer can generate appropriate tokens.
        """
        return None  # Default implementation - no reverse auth support
