from __future__ import annotations

from abc import ABC
from typing import Optional

from naylence.fame.core import FameEnvelope
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DeliveryPolicy(ABC):
    def __init__(self, **kwargs):
        logger.debug("delivery_policy_initialized", policy_type=self.__class__.__name__)

    def is_ack_required(self, envelope: FameEnvelope) -> bool:
        """Determine if the policy requires acknowledgment for message delivery."""
        return False

    @property
    def sender_retry_policy(self) -> Optional[RetryPolicy]:
        """Return retry policy parameters."""
        return None

    @property
    def receiver_retry_policy(self) -> Optional[RetryPolicy]:
        """Return retry policy parameters."""
        return None
