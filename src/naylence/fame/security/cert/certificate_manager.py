"""
Certificate manager interface for node signing material provisioning.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from naylence.fame.core import NodeWelcomeFrame
from naylence.fame.node.node_event_listener import NodeEventListener

if TYPE_CHECKING:
    pass


from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CertificateManager(NodeEventListener, ABC):
    """
    Abstract interface for certificate management in nodes.

    This interface defines the contract for certificate provisioning based on
    security profile and signing configuration. Implementations should handle
    certificate-related logic in a policy-driven manner.
    """

    def __init__(self) -> None:
        super().__init__()

    @abstractmethod
    async def ensure_certificate(
        self,
        welcome_frame: NodeWelcomeFrame,
        ca_service_url: Optional[str] = None,
    ) -> bool: ...


__all__ = ["CertificateManager"]
