from __future__ import annotations

import asyncio
from asyncio import Queue
from typing import Optional

from naylence.fame.core import (
    DEFAULT_POLLING_TIMEOUT_MS,
    Channel,
    FameEnvelope,
    ReadWriteChannel,
)


def in_memory_channel_factory(spec: dict):
    return InMemoryChannel(spec)


class InMemoryChannel(Channel):
    def __init__(self, spec: dict):
        self._spec = spec
        self._queue: Queue[FameEnvelope] = Queue()


class InMemoryReadWriteChannel(ReadWriteChannel):
    def __init__(self, queue: Optional[Queue[FameEnvelope]] = None):
        self._queue = queue if queue is not None else Queue()

    async def receive(self, timeout: int = DEFAULT_POLLING_TIMEOUT_MS) -> Optional[FameEnvelope]:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout / 1000.0)
        except asyncio.TimeoutError:
            return None

    async def acknowledge(self, message_id: str) -> None:
        # No-op for now
        pass

    async def send(self, message: FameEnvelope) -> None:
        await self._queue.put(message)
        return None
