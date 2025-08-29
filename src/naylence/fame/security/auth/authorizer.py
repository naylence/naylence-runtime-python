from typing import Any, Optional, Protocol, runtime_checkable

from naylence.fame.core import AuthorizationContext, FameDeliveryContext, FameEnvelope
from naylence.fame.node.node_like import NodeLike


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
        audience: Optional[str],
        credentials: str | bytes,
    ) -> Optional[AuthorizationContext]: ...

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]: ...

    def create_reverse_authorization_config(self, node: NodeLike) -> Optional[Any]:
        """
        Create authorization configuration for reverse connections (parent -> child).

        This method allows the authorizer to generate credentials/tokens that can be
        used by a parent node when connecting back to this child node. The returned
        configuration should be a ConnectorAuth instance suitable for connector configurations.

        Args:
            node: The node that will receive the reverse connection

        Returns:
            Dict containing authorization configuration, or None if reverse auth not supported.
            Authorizers that have a corresponding TokenIssuer can generate appropriate tokens.
        """
        return None  # Default implementation - no reverse auth support
