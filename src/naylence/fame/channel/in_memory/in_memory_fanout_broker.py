from __future__ import annotations

import asyncio
from typing import Set

from naylence.fame.core import (
    DEFAULT_POLLING_TIMEOUT_MS,
    Closeable,
    ReadWriteChannel,
    WriteChannel,
    extract_envelope_and_context,
)
from naylence.fame.util import logging
from naylence.fame.util.envelope_context import envelope_context
from naylence.fame.util.task_spawner import TaskSpawner

logger = logging.getLogger(__name__)

_SENTINEL = object()


class InMemoryFanoutBroker(TaskSpawner):
    def __init__(self, sink: ReadWriteChannel, _poll_timeout_ms: int = DEFAULT_POLLING_TIMEOUT_MS):
        super().__init__()
        self._sink = sink
        self._subscribers: Set[WriteChannel] = set()
        self._running = False
        self._task: asyncio.Task | None = None
        self._poll_timeout_sec = _poll_timeout_ms / 1000.0

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = self.spawn(self._listen_loop())

    async def stop(self) -> None:
        # 1) prevent new iterations
        self._running = False

        await self._sink.send(_SENTINEL)

        # # 2) cancel the loop (wakes up any blocked receive)
        # if self._task:
        #     self._task.cancel()
        #     try:
        #         # 3) wait for clean shutdown
        #         await self._task
        #     except asyncio.CancelledError:
        #         # expected on cancellation
        #         pass
        #     finally:
        #         self._task = None

        await self.shutdown_tasks(grace_period=3.0)

        # 4) clean up subscribers
        for sub in list(self._subscribers):
            if isinstance(sub, Closeable):
                try:
                    await sub.close()
                except Exception:
                    logger.error("Error closing subscriber %r", sub, exc_info=True)

        self._subscribers.clear()

    async def _listen_loop(self) -> None:
        while self._running:
            try:
                # Non-blocking receive with timeout (1s)
                try:
                    msg = await asyncio.wait_for(self._sink.receive(), timeout=self._poll_timeout_sec)
                except asyncio.TimeoutError:
                    continue

                if msg is None:
                    continue

                if msg is _SENTINEL:
                    self._running = False
                    break

                # Extract envelope from channel message or use direct envelope
                envelope, context = extract_envelope_and_context(msg)

                if envelope is None:
                    continue

                # Deliver to each subscriber individually
                # Send the original message (with context preserved) if it's a FameChannelMessage,
                # otherwise send the envelope directly
                message_to_send = msg if context is not None else envelope

                bad_subs: list = []
                for sub in list(self._subscribers):
                    with envelope_context(envelope):
                        try:
                            await sub.send(message_to_send)
                        except Exception as exc:
                            logger.error(
                                "[InMemoryFanoutBroker] error sending to %r, unsubscribing: %s",
                                sub,
                                exc,
                                exc_info=True,
                            )
                            bad_subs.append(sub)

                # Remove any subscribers that failed
                for sub in bad_subs:
                    self._subscribers.discard(sub)

            except Exception as exc:
                # Critical broker-level error: log and back off, but keep the loop running
                logger.critical(
                    "[InMemoryFanoutBroker] receive loop failed unexpectedly: %s",
                    exc,
                    exc_info=True,
                )
                await asyncio.sleep(0.5)

    def add_subscriber(self, channel: WriteChannel) -> None:
        self._subscribers.add(channel)

    def remove_subscriber(self, channel: WriteChannel) -> None:
        self._subscribers.discard(channel)
