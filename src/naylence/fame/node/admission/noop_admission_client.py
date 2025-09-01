"""
No-op admission client for environments without a welcome/admission service.

This client is useful for:
- Test environments where nodes need to be self-contained
- Development setups without admission infrastructure
- Root nodes that should initialize without upstream dependencies
"""

from typing import List, Optional

from naylence.fame.core import FameEnvelopeWith, NodeWelcomeFrame, create_fame_envelope
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class NoopAdmissionClient(AdmissionClient):
    """
    A no-op admission client that simulates successful admission without
    contacting any external service.

    This client:
    - Returns False for has_upstream() indicating no upstream dependency
    - Generates a synthetic NodeWelcomeFrame for hello() requests
    - Accepts all requested logicals without validation
    - Sets no expiration (perpetual admission)
    """

    def __init__(self, *, system_id: Optional[str] = None, auto_accept_logicals: bool = True):
        """
        Initialize the no-op admission client.

        :param system_id: Default system ID to use if none provided in hello()
        :param auto_accept_logicals: Whether to automatically accept all requested logicals
        """
        self._default_system_id = system_id or "noop-system"
        self._auto_accept_logicals = auto_accept_logicals

    @property
    def has_upstream(self) -> bool:
        """No-op client has no upstream dependency."""
        return False

    async def hello(
        self,
        system_id: str,
        instance_id: str,
        requested_logicals: Optional[List[str]] = None,
    ) -> FameEnvelopeWith[NodeWelcomeFrame]:
        """
        Generate a synthetic welcome frame without contacting any service.

        :param system_id: System identifier (used as-is)
        :param instance_id: Instance identifier (used as-is)
        :param requested_logicals: Logicals to accept (all accepted if auto_accept_logicals=True)
        :returns: Envelope with synthetic NodeWelcomeFrame
        """
        # Use provided system_id or fall back to default
        effective_system_id = system_id or self._default_system_id

        # Accept all requested logicals if auto-accept is enabled
        accepted_logicals = requested_logicals if self._auto_accept_logicals else []

        logger.debug(
            "noop_admission_hello",
            system_id=effective_system_id,
            instance_id=instance_id,
            requested_logicals=requested_logicals,
            accepted_logicals=accepted_logicals,
        )

        # Create synthetic welcome frame
        welcome_frame = NodeWelcomeFrame(
            system_id=effective_system_id,
            instance_id=instance_id,
            accepted_logicals=accepted_logicals or [],
            expires_at=None,  # No expiration for no-op admission
            connection_grants=[],  # No connection grants
        )

        # Wrap in envelope (no specific destination needed)
        envelope = create_fame_envelope(frame=welcome_frame, to=None)

        return envelope  # type: ignore[return-value]

    async def close(self) -> None:
        """No resources to close for no-op client."""
        logger.debug("noop_admission_close")
        pass
