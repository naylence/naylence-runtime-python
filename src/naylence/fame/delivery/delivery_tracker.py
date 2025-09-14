from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field

from naylence.fame.core import (
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
)
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class EnvelopeStatus(str, enum.Enum):
    # The following statuses are used for the outbound tracking only
    PENDING = "pending"
    ACKED = "acked"
    NACKED = "nacked"
    RESPONDED = "responded"
    STREAMING = "streaming"
    TIMED_OUT = "timed_out"
    FAILED = "failed"

    # The following statuses are used for the inbound tracking only
    RECEIVED = "received"
    HANDLED = "handled"
    FAILED_TO_HANDLE = "failed_to_handle"


class MailboxType(str, enum.Enum):
    INBOX = "inbox"
    OUTBOX = "outbox"


class TrackedEnvelope(BaseModel):
    """Information about a tracked envelope."""

    model_config = ConfigDict(arbitrary_types_allowed=True)  # For FameAddress and FameEnvelope

    timeout_at_ms: int = Field(
        ..., description="Timestamp (ms) when the next timer event should fire (retry or final timeout)."
    )
    overall_timeout_at_ms: int = Field(
        ..., description="Absolute deadline in ms for the envelope; never changes."
    )
    expected_response_type: FameResponseType = Field(
        ..., description="Bitmask indicating which response types are expected (ACK, REPLY, etc)."
    )
    created_at_ms: int = Field(..., description="Timestamp (ms) when the envelope was created.")
    attempt: int = Field(default=0, description="Current delivery attempt count.")
    status: EnvelopeStatus = Field(
        default=EnvelopeStatus.PENDING, description="Current status of the tracked envelope."
    )
    meta: Dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary metadata for the tracked envelope."
    )
    inserted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC datetime when the envelope was inserted into tracking.",
    )

    mailbox_type: Optional[MailboxType] = Field(
        default=None, description="Type of mailbox where the envelope is tracked (inbox or outbox)."
    )
    # Store the original envelope for retries
    original_envelope: FameEnvelope = Field(
        ..., description="The original FameEnvelope being tracked (used for retries)."
    )
    service_name: Optional[str] = Field(
        default=None, description="Optional name of the service handling this envelope."
    )

    @property
    def envelope_id(self) -> str:
        """Get the envelope ID from the original envelope."""
        return self.original_envelope.id

    @property
    def correlation_id(self) -> Optional[str]:
        """Get the correlation ID from the original envelope."""
        return self.original_envelope.corr_id

    @property
    def expect_ack(self) -> bool:
        """Check if ACK is expected based on expected_response_type."""
        return bool(self.expected_response_type & FameResponseType.ACK)

    @property
    def expect_reply(self) -> bool:
        """Check if reply is expected based on expected_response_type."""
        return bool(self.expected_response_type & FameResponseType.REPLY)


class DeliveryTracker(ABC):
    def __init__(self) -> None:
        self._event_handlers: list[DeliveryTrackerEventHandler] = []

    @abstractmethod
    async def track(
        self,
        envelope: FameEnvelope,
        *,
        timeout_ms: int,
        expected_response_type: FameResponseType,
        retry_policy: Optional[RetryPolicy] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[TrackedEnvelope]: ...

    @abstractmethod
    async def await_ack(self, envelope_id: str, *, timeout_ms: Optional[int] = None) -> FameEnvelope: ...

    @abstractmethod
    async def await_reply(self, envelope_id: str, *, timeout_ms: Optional[int] = None) -> FameEnvelope: ...

    @abstractmethod
    async def on_envelope_delivered(
        self, inbox_name: str, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> Optional[TrackedEnvelope]: ...

    @abstractmethod
    async def on_envelope_handled(
        self, envelope: TrackedEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None: ...

    @abstractmethod
    async def on_envelope_handle_failed(
        self,
        inbox_name: str,
        envelope: TrackedEnvelope,
        context: Optional[FameDeliveryContext] = None,
        error: Optional[Exception] = None,
        is_final_failure: bool = False,
    ) -> None: ...

    @abstractmethod
    async def update_tracked_envelope(self, envelope: TrackedEnvelope) -> None:
        """Update a tracked envelope in persistent storage."""
        ...

    def iter_stream(self, envelope_id: str, *, timeout_ms: Optional[int] = None) -> AsyncIterator[Any]: ...

    @abstractmethod
    async def on_ack(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None: ...

    @abstractmethod
    async def on_nack(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None: ...

    @abstractmethod
    async def get_tracked_envelope(self, envelope_id: str) -> Optional[TrackedEnvelope]: ...

    @abstractmethod
    async def list_pending(self) -> list[TrackedEnvelope]: ...

    @abstractmethod
    async def cleanup(self) -> None: ...

    @abstractmethod
    async def recover_pending(self) -> None: ...

    @abstractmethod
    async def list_inbound(
        self, filter: Optional[Callable[[TrackedEnvelope], bool]] = None
    ) -> list[TrackedEnvelope]:
        """List inbound envelopes that match the given filter."""
        ...

    # Inbox DLQ API
    @abstractmethod
    async def add_to_inbox_dlq(
        self, tracked_envelope: TrackedEnvelope, reason: Optional[str] = None
    ) -> None:
        """Add a tracked envelope to the inbox dead letter queue."""
        ...

    @abstractmethod
    async def get_from_inbox_dlq(self, envelope_id: str) -> Optional[TrackedEnvelope]:
        """Get a specific envelope from the inbox DLQ by envelope ID."""
        ...

    @abstractmethod
    async def list_inbox_dlq(self) -> list[TrackedEnvelope]:
        """List all envelopes currently in the inbox DLQ."""
        ...

    @abstractmethod
    async def purge_inbox_dlq(self, predicate: Optional[Callable[[TrackedEnvelope], bool]] = None) -> int:
        """Delete inbox DLQ entries. Returns the number of deleted entries."""
        ...

    def add_event_handler(self, event_handler: DeliveryTrackerEventHandler) -> None:
        self._event_handlers.append(event_handler)


class DeliveryTrackerEventHandler(Protocol):
    async def on_envelope_timeout(self, envelope: TrackedEnvelope) -> None:
        pass

    async def on_envelope_acked(self, envelope: TrackedEnvelope) -> None:
        pass

    async def on_envelope_nacked(self, envelope: TrackedEnvelope, reason: Optional[str]) -> None:
        pass

    async def on_envelope_replied(self, envelope: TrackedEnvelope, reply_envelope: FameEnvelope) -> None:
        pass
