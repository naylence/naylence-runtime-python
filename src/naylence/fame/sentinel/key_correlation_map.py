"""
Correlation-ID based routing for key requests and announces.

This module provides a TTL-based mapping to remember where key requests
originated from, allowing key announces to be routed back correctly
through sentinels in pooled address scenarios.
"""

import asyncio
import time
from collections import OrderedDict
from typing import Optional, Union

from naylence.fame.constants.ttl_constants import DEFAULT_KEY_CORRELATION_TTL_SEC
from naylence.fame.util.logging import getLogger
from naylence.fame.util.ttl_validation import validate_key_correlation_ttl_sec

logger = getLogger(__name__)


class KeyCorrelationMap:
    """
    TTL-based LRU mapping for correlation_id → route.

    This class maintains a mapping of key request correlation IDs to their
    originating routes, allowing key announces to be properly routed back
    in pooled address scenarios where:
    child A -> sentinel -> child B (key request)
    child B -> sentinel -> child A (key announce)
    """

    def __init__(
        self,
        ttl_sec: Union[int, float] = DEFAULT_KEY_CORRELATION_TTL_SEC,
        max_entries: int = 2048,
    ):
        """
        Initialize the correlation map.

        Args:
            ttl_sec: Time-to-live for entries in seconds
            max_entries: Maximum number of entries to keep
        """
        self._ttl = validate_key_correlation_ttl_sec(ttl_sec) or ttl_sec
        self._data: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._max = max_entries

    def add(self, corr_id: str, route: str) -> None:
        """
        Add a correlation ID -> route mapping.

        Args:
            corr_id: The correlation ID from the key request
            route: The route where the request originated from
        """
        now = time.time()
        # Remove existing entry if present (to update position in LRU)
        self._data.pop(corr_id, None)
        self._data[corr_id] = (route, now + self._ttl)
        self._evict()

        logger.trace("key_corr_added", corr_id=corr_id, route=route, ttl=self._ttl)

    def pop(self, corr_id: str) -> Optional[str]:
        """
        Remove and return the route for a correlation ID.

        Args:
            corr_id: The correlation ID to look up

        Returns:
            The route if found and not expired, None otherwise
        """
        entry = self._data.pop(corr_id, None)
        if not entry:
            logger.trace("key_corr_not_found", corr_id=corr_id)
            return None

        route, exp = entry
        if exp < time.time():
            logger.trace("key_corr_expired", corr_id=corr_id, route=route)
            return None

        logger.trace("key_corr_found", corr_id=corr_id, route=route)
        return route

    def _evict(self) -> None:
        """Evict entries based on LRU and TTL."""
        # LRU eviction
        while len(self._data) > self._max:
            old_corr_id, (old_route, _) = self._data.popitem(last=False)
            logger.trace("key_corr_lru_evicted", corr_id=old_corr_id, route=old_route)

        # TTL eviction
        now = time.time()
        expired = [k for k, (_, exp) in self._data.items() if exp < now]
        for k in expired:
            route, _ = self._data.pop(k)
            logger.trace("key_corr_ttl_evicted", corr_id=k, route=route)

    async def run_cleanup(self, interval: float = 5.0) -> None:
        """
        Background task that evicts expired entries.

        Args:
            interval: Cleanup interval in seconds
        """
        logger.debug("key_corr_cleanup_started", interval=interval)
        try:
            while True:
                await asyncio.sleep(interval)
                self._evict()
        except asyncio.CancelledError:
            logger.debug("key_corr_cleanup_cancelled")
            raise
        except Exception as e:
            logger.error("key_corr_cleanup_error", error=str(e), exc_info=True)

    def size(self) -> int:
        """Return the current number of entries."""
        return len(self._data)
