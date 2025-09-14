import random

from naylence.fame.factory import ResourceConfig


class RetryPolicy(ResourceConfig):
    """Configuration for retry behavior."""

    type: str = "RetryPolicy"

    max_retries: int = 0
    base_delay_ms: int = 200
    max_delay_ms: int = 10_000
    jitter_ms: int = 50
    backoff_factor: float = 2.0

    def next_delay_ms(self, attempt: int) -> int:
        """Calculate the next retry delay based on attempt number."""
        if attempt <= 0:
            delay = self.base_delay_ms
        else:
            delay = int(self.base_delay_ms * (self.backoff_factor**attempt))

        # Apply symmetric random jitter in the range [-jitter_ms, +jitter_ms]
        if self.jitter_ms and self.jitter_ms > 0:
            jitter = random.randint(-self.jitter_ms, self.jitter_ms)
            delay += jitter

        # Clamp to valid range
        delay = max(0, min(delay, self.max_delay_ms))
        return delay
