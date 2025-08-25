"""
Null object pattern implementation for key management when no key manager is needed.
"""

from typing import Optional

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.security.keys.key_management_handler_base import (
    KeyManagementHandlerBase,
)


class NullKeyManagementHandler(KeyManagementHandlerBase):
    """A null object pattern for key management when no key manager is available."""

    def __init__(self):
        super().__init__()

    async def start(self):
        """Start the null key management handler (no-op)."""
        self._is_started = True

    async def stop(self):
        """Stop the null key management handler (no-op)."""
        self._is_started = False

    async def accept_key_announce(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Accept key announce (no-op)."""
        pass

    async def retry_pending_key_requests_after_attachment(self):
        """Retry pending key requests after attachment (no-op)."""
        pass
