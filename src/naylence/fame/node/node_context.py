from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import Field

from naylence.fame.core import FameDeliveryContext
from naylence.fame.core.protocol.delivery_context import (
    AuthorizationContext,
    SecurityContext,
)


class FameNodeAuthorizationContext(AuthorizationContext):
    """Node-specific authorization context with rich claims."""

    sub: Optional[str] = Field(default=None)
    aud: Optional[str] = Field(default=None)
    assigned_path: Optional[str] = Field(default=None)
    accepted_capabilities: Optional[List[str]] = Field(default=None)
    accepted_logicals: Optional[List[str]] = Field(default=None)
    instance_id: Optional[str] = Field(default=None)
    scopes: Optional[List[str]] = Field(default=None)
    attach_expires_at: Optional[datetime] = Field(default=None)


class FameAuthorizedDeliveryContext(FameDeliveryContext):
    authorization: Optional[FameNodeAuthorizationContext] = Field(default=None)


def create_node_delivery_context(
    *,
    from_system_id: Optional[str] = None,
    from_connector: Optional[Any] = None,
    origin_type: Optional[Any] = None,
    authorization: Optional[FameNodeAuthorizationContext] = None,
    **kwargs,
) -> FameDeliveryContext:
    """
    Create a delivery context with node-specific authorization context.

    This helper ensures that the authorization context is properly typed
    and integrated into the core delivery context structure.
    """
    security_context = None
    if authorization:
        security_context = SecurityContext(authorization=authorization)

    return FameDeliveryContext(
        from_system_id=from_system_id,
        from_connector=from_connector,
        origin_type=origin_type,
        security=security_context,
        **kwargs,
    )
