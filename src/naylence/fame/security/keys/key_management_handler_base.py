"""
Base class for key management handlers.
"""

from abc import ABC, abstractmethod
from typing import Optional

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.util.task_spawner import TaskSpawner


class KeyManagementHandlerBase(TaskSpawner, ABC):
    """Base class for key management handlers."""

    def __init__(self):
        TaskSpawner.__init__(self)
        self._is_started = False

    @abstractmethod
    async def start(self):
        """Start the key management handler."""
        pass

    @abstractmethod
    async def stop(self):
        """Stop the key management handler."""
        pass

    @abstractmethod
    async def accept_key_announce(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Accept key announce."""
        pass

    @abstractmethod
    async def retry_pending_key_requests_after_attachment(self):
        """Retry pending key requests after attachment."""
        pass

    async def accept_key_request(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext]):
        """Accept key request (default implementation)."""
        pass

    async def process_envelope(self, envelope: FameEnvelope, context: FameDeliveryContext):
        """Process envelope (default implementation)."""
        pass

    async def should_process_envelope(self, envelope: FameEnvelope, context: FameDeliveryContext) -> bool:
        """Check if envelope should be processed (default implementation)."""
        return False

    async def should_request_key(self, envelope: FameEnvelope, context: FameDeliveryContext) -> bool:
        """Check if key should be requested (default implementation)."""
        return False

    async def should_request_encryption_key(
        self, envelope: FameEnvelope, context: FameDeliveryContext
    ) -> bool:
        """Check if encryption key should be requested (default implementation)."""
        return False

    async def request_key(self, envelope: FameEnvelope, context: FameDeliveryContext):
        """Request key (default implementation)."""
        pass

    async def request_encryption_key(self, envelope: FameEnvelope, context: FameDeliveryContext):
        """Request encryption key (default implementation)."""
        pass

    async def has_key(self, kid: str) -> bool:
        """Check if key exists (default implementation)."""
        return False
