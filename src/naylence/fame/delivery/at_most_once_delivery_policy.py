from __future__ import annotations

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AtMostOnceDeliveryPolicy(DeliveryPolicy):
    """Message delivery policy that ensures messages are delivered at most once."""

    def is_ack_required(self, envelope) -> bool:
        """At-most-once delivery does not require ACKs."""
        return False
