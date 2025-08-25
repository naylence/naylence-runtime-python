"""
NoSecurityManager - A security manager that provides no security components.

This implementation provides a completely open security posture with no encryption,
signing, verification, or other security features. It's intended for development,
testing, or scenarios where security is handled at a different layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.policy import NoSecurityPolicy
from naylence.fame.security.security_manager import SecurityManager
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
    from naylence.fame.node.node_like import NodeLike
    from naylence.fame.node.secure_channel_frame_handler import (
        SecureChannelFrameHandler,
    )
    from naylence.fame.security.cert.certificate_manager import CertificateManager
    from naylence.fame.security.encryption.encryption_manager import EncryptionManager
    from naylence.fame.security.keys.key_manager import KeyManager
    from naylence.fame.security.policy import SecurityPolicy
    from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
    from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier

logger = getLogger(__name__)


class NoSecurityManager(SecurityManager):
    """
    A security manager implementation that provides no security features.

    This implementation returns None for all security components and provides
    no-op implementations for all event handlers. It's suitable for scenarios
    where no security is required or security is handled at a different layer.
    """

    def __init__(self):
        """Initialize the no-security manager with a NoSecurityPolicy and minimal components."""
        self._policy = NoSecurityPolicy()

        # Create a minimal no-op authorizer to satisfy Sentinel requirements
        # This authorizer allows all connections without any actual security checks
        try:
            from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer

            self._authorizer = NoopAuthorizer()
        except ImportError:
            # Fallback if NoopAuthorizer doesn't exist
            self._authorizer = None

    @property
    def policy(self) -> SecurityPolicy:
        """Get the no-security policy."""
        return self._policy

    @property
    def envelope_signer(self) -> Optional[EnvelopeSigner]:
        """Get the envelope signer (always None)."""
        return None

    @property
    def envelope_verifier(self) -> Optional[EnvelopeVerifier]:
        """Get the envelope verifier (always None)."""
        return None

    @property
    def encryption(self) -> Optional[EncryptionManager]:
        """Get the encryption manager (always None)."""
        return None

    @property
    def key_manager(self) -> Optional[KeyManager]:
        """Get the key manager (always None)."""
        return None

    @property
    def supports_overlay_security(self) -> bool:
        return False

    @property
    def authorizer(self) -> Optional[Authorizer]:
        """Get the node attach authorizer (minimal no-op authorizer)."""
        return self._authorizer

    @property
    def certificate_manager(self) -> Optional[CertificateManager]:
        """Get the certificate manager (always None)."""
        return None

    @property
    def envelope_security_handler(self) -> Optional[EnvelopeSecurityHandler]:
        """Get the envelope security handler (always None)."""
        return None

    @property
    def secure_channel_frame_handler(self) -> Optional[SecureChannelFrameHandler]:
        """Get the channel frame handler (always None)."""
        return None

    def get_encryption_key_id(self) -> Optional[str]:
        """Get the encryption key ID (always None)."""
        return None

    def get_shareable_keys(self) -> Any:
        """Get keys to provide to child nodes (always None for no security)."""
        return None

    # NodeEventListener implementation - all no-op

    async def on_node_initialized(self, node: NodeLike) -> None:
        """Handle node initialization (no-op)."""
        logger.debug("noop_security_manager_node_initialized", node_id=getattr(node, "id", None))

    async def on_node_started(self, node: NodeLike) -> None:
        """Handle node start (no-op)."""
        logger.debug("noop_security_manager_node_started", node_id=getattr(node, "id", None))

    async def on_node_stopped(self, node: NodeLike) -> None:
        """Handle node stop (no-op)."""
        logger.debug("noop_security_manager_node_stopped", node_id=getattr(node, "id", None))

    async def on_welcome(self, welcome_frame: Any) -> None:
        """Handle child welcome event (no-op)."""
        logger.debug("noop_security_manager_child_welcome")

    async def on_heartbeat_received(self, envelope: Any) -> None:
        """Handle heartbeat received event (no-op)."""
        logger.debug("noop_security_manager_heartbeat_received")

    async def on_child_attach(
        self,
        *,
        child_system_id: str,
        child_keys: Any,
        node_like: NodeLike,
        origin_type: Any = None,
        assigned_path: Optional[str] = None,
        old_assigned_path: Optional[str] = None,
        is_rebind: bool = False,
    ) -> None:
        """Handle child attachment (no-op for no security)."""
        logger.debug("noop_security_manager_child_attach", child_system_id=child_system_id)
