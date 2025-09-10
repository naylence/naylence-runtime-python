from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field

from naylence.fame.core import (
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
)
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class EnvelopeStatus(str, enum.Enum):
    PENDING = "pending"
    ACKED = "acked"
    NACKED = "nacked"
    RESPONDED = "responded"
    STREAMING = "streaming"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class TrackedEnvelope(BaseModel):
    """Information about a tracked envelope."""

    model_config = ConfigDict(arbitrary_types_allowed=True)  # For FameAddress and FameEnvelope

    envelope_id: str
    corr_id: Optional[str] = None
    target: Optional[FameAddress] = None
    timeout_at_ms: int  # When the next timer event should fire (retry or final timeout)
    overall_timeout_at_ms: int  # The absolute deadline - never changes
    expected_response_type: FameResponseType
    created_at_ms: int
    attempt: int = 0
    status: EnvelopeStatus = EnvelopeStatus.PENDING
    meta: Dict[str, Any] = Field(default_factory=dict)
    inserted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Store the original envelope for retries
    original_envelope: Optional[FameEnvelope] = None

    @property
    def correlation_id(self) -> Optional[str]:
        """Alias for corr_id for backward compatibility."""
        return self.corr_id

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
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None: ...

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
    async def on_reply(
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
