from __future__ import annotations

from typing import Optional

from naylence.fame.core import DataFrame, FameEnvelope
from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AtLeastOnceDeliveryPolicy(DeliveryPolicy):
    """Message delivery policy that ensures messages are delivered at least once."""

    def __init__(
        self,
        sender_retry_policy: Optional[RetryPolicy] = None,
        receiver_retry_policy: Optional[RetryPolicy] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._sender_retry_policy = sender_retry_policy or RetryPolicy()
        self._receiver_retry_policy = receiver_retry_policy or RetryPolicy()

    def is_ack_required(self, envelope: FameEnvelope) -> bool:
        # For now require ACKs for DataFrames only
        return isinstance(envelope.frame, DataFrame)
        # return isinstance(envelope.frame, DataFrame) and (
        #     envelope.rtype is None or envelope.rtype & FameResponseType.ACK == FameResponseType.ACK
        # )

    @property
    def sender_retry_policy(self) -> Optional[RetryPolicy]:
        """Return retry policy parameters for sender-side retries."""
        return self._sender_retry_policy

    @property
    def receiver_retry_policy(self) -> Optional[RetryPolicy]:
        """Return retry policy parameters for receiver-side retries."""
        return self._receiver_retry_policy
