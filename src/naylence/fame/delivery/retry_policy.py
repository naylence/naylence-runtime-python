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
        delay = min(delay, self.max_delay_ms)
        # Simple jitter
        if self.jitter_ms:
            delay += int(self.jitter_ms / 2)
        return delay
