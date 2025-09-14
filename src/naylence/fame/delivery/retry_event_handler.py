from typing import Optional, Protocol

from naylence.fame.core import FameDeliveryContext, FameEnvelope


class RetryEventHandler(Protocol):
    async def on_retry_needed(
        self,
        envelope: FameEnvelope,
        attempt: int,
        next_delay_ms: int,
        context: Optional[FameDeliveryContext] = None,
    ) -> None: ...
