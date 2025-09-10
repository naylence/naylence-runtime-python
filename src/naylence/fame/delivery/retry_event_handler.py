from typing import Protocol

from naylence.fame.core import FameEnvelope


class RetryEventHandler(Protocol):
    async def on_retry_needed(self, envelope: FameEnvelope, attempt: int, next_delay_ms: int) -> None: ...
