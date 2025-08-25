"""
Certificate manager interface for node signing material provisioning.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from naylence.fame.core import NodeWelcomeFrame
from naylence.fame.node.node_event_listener import NodeEventListener

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike


from naylence.fame.security.policy.security_policy import SigningConfig, SigningMaterial
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CertificateManager(NodeEventListener, ABC):
    """
    Abstract interface for certificate management in nodes.

    This interface defines the contract for certificate provisioning based on
    security profile and signing configuration. Implementations should handle
    certificate-related logic in a policy-driven manner.
    """

    def __init__(self, signing_config: Optional[SigningConfig] = None) -> None:
        super().__init__()
        self.signing_config = signing_config or SigningConfig()

    async def on_node_started(self, node: NodeLike) -> None:
        """
        Handle certificate provisioning when a node has started.

        This method implements the NodeEventListener interface and is called
        when a node has completed initialization and is ready for operation.

        Args:
            node: The node that has been started
        """
        # Only provision certificates for root nodes (nodes without parents)
        if node.has_parent:
            logger.debug(
                "skipping_certificate_provisioning_for_child_node",
                node_id=node.id,
                has_parent=node.has_parent,
            )
            return

        # Set up crypto provider context
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        crypto_provider = get_crypto_provider()
        crypto_provider.set_node_context_from_nodelike(node)

        # Provision certificate for root node
        success = await self.ensure_root_certificate(
            node_id=node.id,
            physical_path=node.physical_path,
            logicals=list(node.accepted_logicals),
        )

        if not success:
            logger.error(
                "node_startup_failed_certificate_validation",
                node_id=node.id,
                physical_path=node.physical_path,
                message="Node cannot start due to certificate validation failure",
            )
            # TODO: Consider how to properly fail node startup
            # For now, we raise an exception to prevent the node from continuing
            raise RuntimeError(f"Node {node.id} cannot start: certificate validation failed")

    @abstractmethod
    async def ensure_root_certificate(self, node_id: str, physical_path: str, logicals: list[str]) -> bool:
        """
        Handle certificate provisioning for root node startup.

        This method is called when a root node is starting up and may need
        certificate provisioning based on the configured security policy.

        Args:
            node_id: The unique identifier for the node
            physical_path: The physical path where the node is located
            logicals: List of logical addresses/services the node provides

        Returns:
            bool: True if certificate provisioning was successful or not needed,
                  False if there was an error that should prevent node startup
        """
        pass

    async def on_welcome(self, welcome_frame) -> None:
        """
        Handle certificate provisioning after receiving a welcome frame.

        Args:
            welcome_frame: NodeWelcomeFrame from admission process

        Returns:
            True if certificate is available or not needed, False if provisioning failed
        """
        # Check if the welcome frame specifies X.509 requirement
        needs_x509 = False

        security_settings = getattr(welcome_frame, "security_settings", None)
        if security_settings:
            needs_x509 = security_settings.signing_material == SigningMaterial.X509_CHAIN
        else:
            # Fall back to local signing config
            needs_x509 = self.signing_config.signing_material == SigningMaterial.X509_CHAIN

        if not needs_x509:
            logger.debug(
                "certificate_not_required_by_welcome",
                security_settings=security_settings,
            )
            return

        logger.debug(
            "provisioning_certificate_after_welcome",
            node_id=getattr(welcome_frame, "system_id", None),
            assigned_path=getattr(welcome_frame, "assigned_path", None),
        )

        success = await self.ensure_non_root_certificate(
            welcome_frame=welcome_frame,
        )

        if not success:
            node_id = welcome_frame.system_id or "unknown"
            assigned_path = welcome_frame.assigned_path
            logger.error(
                "certificate_provisioning_failed_for_child",
                node_id=node_id,
                assigned_path=assigned_path,
                message="Certificate provisioning or validation failed - node cannot proceed",
            )
            # Child nodes must have valid certificates when X509_CHAIN is required
            # Failing to obtain a certificate is a security failure
            raise RuntimeError(f"Child node {node_id} cannot proceed: certificate validation failed")

    @abstractmethod
    async def ensure_non_root_certificate(
        self,
        welcome_frame: NodeWelcomeFrame,
        ca_service_url: Optional[str] = None,
    ) -> bool: ...


__all__ = ["CertificateManager"]
