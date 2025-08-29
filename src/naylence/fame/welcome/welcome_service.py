from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from naylence.fame.core import (
    NodeHelloFrame,
    NodeWelcomeFrame,
)
from naylence.fame.security.auth.authorizer import Authorizer


@runtime_checkable
class WelcomeService(Protocol):
    """
    Admission controller façade called by the bootstrap connector
    OR by a RoutingNode proxy.
    """

    @property
    def authorizer(self) -> Optional[Authorizer]:
        return None

    async def handle_hello(self, hello: NodeHelloFrame) -> NodeWelcomeFrame: ...
