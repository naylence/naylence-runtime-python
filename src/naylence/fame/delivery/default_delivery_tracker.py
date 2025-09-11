"""
Default envelope tracker implementation that uses a pluggable KeyValueStore.

This implementation provides full tracking functionality while being agnostic
about the underlying storage mechanism - it can work with in-memory, persistent,
or any other KeyValueStore implementation.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, AsyncIterator, Dict, Optional

from naylence.fame.core import (
    DeliveryAckFrame,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    generate_id,
)
from naylence.fame.delivery.delivery_tracker import (
    DeliveryTracker,
    EnvelopeStatus,
    TrackedEnvelope,
)
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.util import logging
from naylence.fame.util.formatter import AnsiColor, color, format_timestamp
from naylence.fame.util.task_spawner import TaskSpawner
from naylence.fame.util.util import pretty_model

logger = logging.getLogger(__name__)


_STREAM_END = object()

ENV_VAR_SHOW_ENVELOPES = "FAME_SHOW_ENVELOPES"

show_envelopes = bool(os.getenv(ENV_VAR_SHOW_ENVELOPES) == "true")


def _timestamp() -> str:
    return color(format_timestamp(), AnsiColor.GRAY)


class DefaultDeliveryTracker(NodeEventListener, DeliveryTracker, TaskSpawner):
    """
    Default envelope tracker implementation using a pluggable KeyValueStore.

    This implementation provides full tracking functionality including:
    - Ack/nack correlation with futures
    - Reply correlation via correlation IDs
    - Timeout and retry management
    - Event handler integration
    - Persistence via the provided KeyValueStore

    The storage mechanism is completely pluggable - use an in-memory store
    for testing/development or a persistent store for production.
    """

    def __init__(
        self,
        tracker_store: KeyValueStore[TrackedEnvelope],
        # *,
        # retry_handler: Optional[RetryEventHandler] = None,
    ) -> None:
        NodeEventListener.__init__(self)
        DeliveryTracker.__init__(self)
        TaskSpawner.__init__(self)

        self._tracker_store = tracker_store

        # corr_id -> envelope_id, use for replies only, not for ACKs
        self._correlation_to_envelope: dict[str, str] = {}

        self._timers: dict[str, asyncio.Task] = {}

        self._ack_futures: dict[str, asyncio.Future[FameEnvelope]] = {}
        self._reply_futures: dict[str, asyncio.Future[FameEnvelope]] = {}

        self._stream_queues: dict[str, asyncio.Queue[Any]] = {}
        self._stream_done: dict[str, asyncio.Event] = {}

        self._lock = asyncio.Lock()
        self._node: NodeLike | None = None
        logger.debug("created_default_delivery_tracker")

    async def on_node_started(self, node: NodeLike) -> None:
        self._node = node

    async def on_node_preparing_to_stop(self, node: NodeLike) -> None:
        """Wait for pending acknowledgments until their timeouts expire before node stops."""
        await self._wait_for_pending_acks()

    async def on_node_stopped(self, node: NodeLike) -> None:
        await self.cleanup()
        await self.shutdown_tasks()

    async def _wait_for_pending_acks(self) -> None:
        """Wait for pending acknowledgments until their timeouts expire."""
        logger.debug("tracker_node_preparing_to_stop_waiting_for_pending_acks")

        # Get all pending envelopes that are expecting ACKs
        pending_acks = []
        async with self._lock:
            for envelope_id, future in list(self._ack_futures.items()):
                if not future.done():
                    pending_acks.append((envelope_id, future))

        if not pending_acks:
            logger.debug("tracker_no_pending_acks_to_wait_for")
            return

        logger.debug("tracker_waiting_for_pending_acks", count=len(pending_acks))

        # Wait for each ACK future with its individual timeout
        for envelope_id, future in pending_acks:
            try:
                # Get the tracked envelope to determine its timeout
                tracked = await self._tracker_store.get(envelope_id)
                if not tracked:
                    continue

                # Calculate remaining timeout
                now_ms = int(time.time() * 1000)
                remaining_ms = max(0, tracked.overall_timeout_at_ms - now_ms)

                if remaining_ms > 0:
                    timeout_seconds = remaining_ms / 1000.0
                    logger.debug(
                        "tracker_waiting_for_ack", envelope_id=envelope_id, timeout_seconds=timeout_seconds
                    )

                    try:
                        await asyncio.wait_for(future, timeout=timeout_seconds)
                        logger.debug("tracker_received_ack", envelope_id=envelope_id)
                    except asyncio.TimeoutError:
                        logger.debug("tracker_ack_timeout_expired", envelope_id=envelope_id)
                    except Exception as e:
                        logger.debug("tracker_ack_wait_error", envelope_id=envelope_id, error=str(e))
                    else:
                        await self._tracker_store.delete(envelope_id)
                else:
                    logger.debug("tracker_ack_already_expired", envelope_id=envelope_id)

            except Exception as e:
                logger.error("tracker_error_waiting_for_ack", envelope_id=envelope_id, error=str(e))

        logger.debug("tracker_finished_waiting_for_pending_acks")

    async def on_forward_upstream_complete(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: FameDeliveryContext | None = None,
    ) -> Optional[FameEnvelope]:
        if show_envelopes:
            print(
                f"\n{_timestamp()} - {color('Forwarded envelope to upstream', AnsiColor.BLUE)} 🚀\n{
                    pretty_model(envelope)
                }"
            )
        return envelope

    async def on_forward_to_route_complete(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: FameDeliveryContext | None = None,
    ) -> Optional[FameEnvelope]:
        if show_envelopes:
            print(
                f"\n{_timestamp()} - {
                    color('Forwarded envelope to route "' + next_segment + '"', AnsiColor.BLUE)
                } 🚀\n{pretty_model(envelope)}"
            )
        return envelope

    async def on_forward_to_peer_complete(
        self,
        node: NodeLike,
        peer_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: FameDeliveryContext | None = None,
    ) -> Optional[FameEnvelope]:
        if show_envelopes:
            print(
                f"\n{_timestamp()} - '{
                    color('Forwarded envelope to peer "' + peer_segment + '"', AnsiColor.BLUE)
                }' 🚀\n{pretty_model(envelope)}"
            )
        return envelope

    async def on_heartbeat_sent(self, envelope: FameEnvelope) -> None:
        if show_envelopes:
            print(
                f"\n{_timestamp()} - {color('Sent envelope', AnsiColor.BLUE)} 🚀\n{pretty_model(envelope)}"
            )

    async def on_envelope_delivered(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None:
        logger.debug(
            "tracker_envelope_delivered",
            envp_id=envelope.id,
            corr_id=envelope.corr_id,
            rtype=FameResponseType(envelope.rtype) if envelope.rtype else "Unknown",
            frame_type=type(envelope.frame).__name__,
        )

        if not envelope.corr_id:
            logger.debug("tracker_envelope_delivered_no_corr_id", envelope_id=envelope.id)  # type: ignore

        if isinstance(envelope.frame, DeliveryAckFrame):
            # Ack handling
            assert envelope.frame.ref_id
            if envelope.frame.ok:
                await self.on_ack(envelope, context)
            else:
                await self.on_nack(envelope, context)

        elif envelope.corr_id:
            await self.on_reply(envelope, context)

            # When reply itself requires an ack, send it
            if envelope.rtype and bool(envelope.rtype & FameResponseType.ACK):
                await self._send_ack(envelope)

    async def _send_ack(self, envelope: FameEnvelope) -> None:
        assert self._node is not None

        if envelope.reply_to is None:
            logger.error("cannot_send_ack_no_reply_to", envp_id=envelope.id)
            return

        if envelope.corr_id is None:
            logger.error("cannot_send_ack_no_corr_id", envp_id=envelope.id)
            return

        logger.debug(
            "tracker_sending_ack", envp_id=envelope.id, to=envelope.reply_to, corr_id=envelope.corr_id
        )

        ack_env = self._node.envelope_factory.create_envelope(
            to=envelope.reply_to,
            frame=DeliveryAckFrame(ok=True, ref_id=envelope.id),
            corr_id=envelope.corr_id,
            trace_id=envelope.trace_id,
        )
        await self._node.send(ack_env)

    async def track(
        self,
        envelope: FameEnvelope,
        *,
        timeout_ms: int,
        expected_response_type: FameResponseType,
        retry_policy: Optional[RetryPolicy] = None,
        retry_handler: Optional[RetryEventHandler] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[TrackedEnvelope]:
        now_ms = int(time.time() * 1000)

        if envelope.corr_id:
            corr_id = envelope.corr_id
        else:
            corr_id = envelope.corr_id = generate_id()

        async with self._lock:
            if envelope.id in self._ack_futures:
                logger.debug("tracker_envelope_already_tracked", envp_id=envelope.id)
                return None

            existing_env_id = self._correlation_to_envelope.get(envelope.corr_id)

            if expected_response_type & (FameResponseType.REPLY | FameResponseType.STREAM):
                if existing_env_id:
                    logger.debug(
                        "envelope_already_tracked_for_replies",
                        envp_id=envelope.id,
                        corr_id=corr_id,
                        expected_response_type=expected_response_type.name,
                    )
                    return None

                self._correlation_to_envelope[envelope.corr_id] = envelope.id

            # Create ack future if needed
            if expected_response_type & FameResponseType.ACK:
                self._ack_futures[envelope.id] = asyncio.get_running_loop().create_future()

            # Create reply future if needed
            if expected_response_type & FameResponseType.REPLY:
                self._reply_futures[envelope.id] = asyncio.get_running_loop().create_future()

            # Create stream end future if needed
            if expected_response_type & FameResponseType.STREAM:
                self._stream_queues[envelope.id] = asyncio.Queue()
                self._stream_done[envelope.id] = asyncio.Event()

        tracked = TrackedEnvelope(
            envelope_id=envelope.id,
            corr_id=corr_id,
            target=envelope.to,
            timeout_at_ms=now_ms + (retry_policy.next_delay_ms(0) if retry_policy else timeout_ms),
            overall_timeout_at_ms=now_ms + timeout_ms,
            expected_response_type=expected_response_type,
            created_at_ms=now_ms,
            meta=meta or {},
            original_envelope=envelope,  # Store the envelope directly
        )

        # Persist to storage
        await self._tracker_store.set(envelope.id, tracked)

        # Schedule timeout/retry timer
        await self._schedule_timer(tracked, retry_policy, retry_handler=retry_handler)

        logger.debug(
            "tracker_registered_envelope",
            envp_id=envelope.id,
            corr_id=envelope.corr_id,
            expected_response=expected_response_type.name,
            target=str(envelope.to) if envelope.to else None,
            timeout_ms=timeout_ms,
        )
        return tracked

    async def await_ack(self, envelope_id: str, *, timeout_ms: Optional[int] = None) -> FameEnvelope:
        async with self._lock:
            future = self._ack_futures.get(envelope_id)

        if not future:
            raise RuntimeError(f"No ack expected for envelope {envelope_id}")

        return await self._await_envelope_future(envelope_id, future, timeout_ms=timeout_ms)

    async def await_reply(self, envelope_id: str, *, timeout_ms: Optional[int] = None) -> Any:
        async with self._lock:
            future = self._reply_futures.get(envelope_id)

        if not future:
            raise RuntimeError(f"No reply expected for envelope {envelope_id}")

        return await self._await_envelope_future(envelope_id, future, timeout_ms=timeout_ms)

    async def _await_envelope_future(
        self,
        envelope_id: str,
        future: asyncio.Future[FameEnvelope],
        timeout_ms: Optional[int] = None,
    ) -> FameEnvelope:
        # Use provided timeout or calculate from tracked envelope
        if timeout_ms is None:
            # Try to get the envelope's configured timeout
            tracked = await self._tracker_store.get(envelope_id)
            if tracked:
                now_ms = int(time.time() * 1000)
                remaining_ms = max(0, tracked.overall_timeout_at_ms - now_ms)
                timeout_seconds = remaining_ms / 1000.0 if remaining_ms > 0 else None
            else:
                timeout_seconds = None
        else:
            timeout_seconds = timeout_ms / 1000.0

        result: FameEnvelope
        start_time = None
        try:
            if timeout_seconds is not None:
                result = await asyncio.wait_for(future, timeout=timeout_seconds)
            else:
                logger.debug("await_envelope_no_timeout_wait", envelope_id=envelope_id)
                result = await future
        except asyncio.TimeoutError as e:
            end_time = time.time()
            elapsed = end_time - start_time if start_time is not None else 0

            logger.error(
                "await_envelope_timeout_error",
                envelope_id=envelope_id,
                timeout_seconds=timeout_seconds,
                elapsed_seconds=elapsed,
                future_done=future.done(),
                future_cancelled=future.cancelled(),
                future_exception=future.exception() if future.done() and not future.cancelled() else None,
                error=str(e),
            )
            raise asyncio.TimeoutError(f"Timeout waiting for reply or ACK for envelope {envelope_id}")

        return result

    async def on_ack(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        assert isinstance(envelope.frame, DeliveryAckFrame), "Ack must be from a DeliveryAckFrame"
        assert envelope.corr_id, "Reply envelope must have a correlation ID"
        assert envelope.frame.ref_id, "Ack frame must have a reference ID"

        logger.debug(
            "tracker_on_ack", envp_id=envelope.id, corr_id=envelope.corr_id, ref_id=envelope.frame.ref_id
        )

        tracked_envelope = await self._tracker_store.get(envelope.frame.ref_id)

        if not tracked_envelope:
            logger.debug("tracker_ack_for_unknown_envelope", envp_id=envelope.id)
            return

        if tracked_envelope.corr_id != envelope.corr_id:
            logger.debug(
                "tracker_ack_corr_id_mismatch",
                envp_id=envelope.id,
                expected_corr_id=tracked_envelope.corr_id,
                actual_corr_id=envelope.corr_id,
            )
            return

        if tracked_envelope.envelope_id == envelope.id:
            # Received the original envelope instead of an ack, happens in local-to-local calls
            return

        # Update status
        tracked_envelope.status = (
            EnvelopeStatus.ACKED
            if not (tracked_envelope.expected_response_type & FameResponseType.STREAM)
            else tracked_envelope.status
        )
        await self._tracker_store.set(tracked_envelope.envelope_id, tracked_envelope)

        # Resolve ack future
        async with self._lock:
            future = self._ack_futures.pop(tracked_envelope.envelope_id, None)
            logger.debug(
                "tracker_popped_ack_future",
                envp_id=tracked_envelope.envelope_id,
                future_exists=future is not None,
            )

        if future and not future.done():
            future.set_result(envelope)

        # Cancel timer
        await self._clear_timer(tracked_envelope.envelope_id)

        # Notify event handler
        for event_handler in self._event_handlers:
            await event_handler.on_envelope_acked(tracked_envelope)

        logger.debug("tracker_envelope_acked", envp_id=tracked_envelope.envelope_id)

    async def on_nack(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        assert isinstance(envelope.frame, DeliveryAckFrame), "Nack must be from a DeliveryAckFrame"
        assert envelope.corr_id, "Reply envelope must have a correlation ID"
        assert envelope.frame.ref_id, "Ack frame must have a reference ID"

        tracked_envelope = await self._tracker_store.get(envelope.frame.ref_id)

        if not tracked_envelope:
            logger.debug("tracker_nack_for_unknown_envelope", envp_id=envelope.id)
            return

        if tracked_envelope.corr_id != envelope.corr_id:
            logger.debug(
                "tracker_nack_corr_id_mismatch",
                envp_id=envelope.id,
                expected_corr_id=tracked_envelope.corr_id,
                actual_corr_id=envelope.corr_id,
            )
            return

        # Update status and metadata
        tracked_envelope.status = EnvelopeStatus.NACKED
        if envelope.frame.reason:
            tracked_envelope.meta["nack_reason"] = envelope.frame.reason

        await self._tracker_store.set(tracked_envelope.envelope_id, tracked_envelope)

        # Resolve ack future with error
        async with self._lock:
            future = self._ack_futures.pop(tracked_envelope.envelope_id, None)
            logger.debug(
                "tracker_popped_ack_future_on_nack",
                envp_id=tracked_envelope.envelope_id,
                future_exists=future is not None,
            )

        if future and not future.done():
            future.set_exception(RuntimeError(f"Envelope nacked: {envelope.frame.reason or 'unknown'}"))

        stream_queue = self._stream_queues.get(tracked_envelope.envelope_id)
        if stream_queue:
            await stream_queue.put(envelope)
            await stream_queue.put(_STREAM_END)
            ev = self._stream_done.get(tracked_envelope.envelope_id)
            if ev:
                ev.set()

        # Cancel timer
        await self._clear_timer(tracked_envelope.envelope_id)

        # Notify event handler
        for event_handler in self._event_handlers:
            await event_handler.on_envelope_nacked(tracked_envelope, envelope.frame.reason)

        logger.debug(
            "tracker_envelope_nacked",
            envp_id=tracked_envelope.envelope_id,
            reason=envelope.frame.reason,
        )

    async def on_reply(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        assert envelope.corr_id, "Reply envelope must have a correlation ID"

        tracked_envelope_id = self._correlation_to_envelope.get(envelope.corr_id)
        if not tracked_envelope_id:
            logger.debug("tracker_reply_for_unknown_correlation", corr_id=envelope.corr_id)
            return

        tracked_envelope = await self._tracker_store.get(tracked_envelope_id)
        if not tracked_envelope:
            logger.debug("tracker_reply_for_unknown_envelope", envp_id=envelope.id)
            return

        if tracked_envelope.envelope_id == envelope.id:
            # Received the original envelope instead of a reply, happens in local-to-local calls
            return

        if tracked_envelope.expected_response_type & FameResponseType.STREAM:
            # Treat as stream item for metrics only; upstream handles delivery
            await self.on_stream_item(tracked_envelope.envelope_id, envelope)
            return

        # Update status
        tracked_envelope.status = EnvelopeStatus.RESPONDED
        await self._tracker_store.set(tracked_envelope.envelope_id, tracked_envelope)

        # Cancel timer
        await self._clear_timer(tracked_envelope.envelope_id)

        # Resolve reply future
        async with self._lock:
            future = self._reply_futures.pop(tracked_envelope.envelope_id, None)

        if future and not future.done():
            future.set_result(envelope)

        # Notify event handler
        for event_handler in self._event_handlers:
            await event_handler.on_envelope_replied(tracked_envelope, envelope)

        logger.debug(
            "tracked_envelope_replied",
            envp_id=tracked_envelope.envelope_id,
            corr_id=envelope.corr_id,
        )

    async def iter_stream(
        self, envelope_id: str, *, timeout_ms: Optional[int] = None
    ) -> AsyncIterator[Any]:
        stream_queue = self._stream_queues.get(envelope_id)
        done = self._stream_done.get(envelope_id)
        if not stream_queue or not done:
            # Not a stream-tracked envelope
            return
            # yield  # make function an iterator

        per_get_timeout = (timeout_ms / 1000.0) if timeout_ms else None
        while True:
            try:
                item = (
                    await asyncio.wait_for(stream_queue.get(), timeout=per_get_timeout)
                    if per_get_timeout
                    else await stream_queue.get()
                )
            except asyncio.TimeoutError as e:
                raise asyncio.TimeoutError(f"stream timeout waiting for next item: {e}")
            if item is _STREAM_END:
                break
            if isinstance(item, Exception):
                raise item
            yield item

    async def on_stream_item(self, envelope_id: str, reponse_env: FameEnvelope) -> None:
        q = self._stream_queues.get(envelope_id)
        if not q:
            return
        logger.debug("tracker_stream_item", envp_id=envelope_id, response_envp_id=reponse_env.id)
        await q.put(reponse_env)

    async def on_stream_end(self, envelope_id: str) -> None:
        entry = await self._tracker_store.get(envelope_id)
        if entry:
            entry.status = EnvelopeStatus.RESPONDED
            await self._tracker_store.set(envelope_id, entry)
        q = self._stream_queues.get(envelope_id)
        if q:
            await q.put(_STREAM_END)
        ev = self._stream_done.get(envelope_id)
        if ev:
            ev.set()

    # async def _get_tracked_envelope(
    #     self, corr_id: str, response_type: FameResponseType,
    # ) -> Optional[TrackedEnvelope]:
    #     async with self._lock:
    #         entry = self._correlation_to_envelope.get(corr_id)

    #     if not entry:
    #         logger.debug("tracker_reply_for_unknown_correlation", corr_id=corr_id)
    #         return None

    #     env_ids = [env_id for env_id, rtype in entry.items() if rtype & response_type]

    #     if envelope_id and envelope_id in env_ids:
    #         return await self._tracker_store.get(envelope_id)

    #     return await self._tracker_store.get(env_ids[0]) if env_ids else None

    async def get_tracked_envelope(self, envelope_id: str) -> Optional[TrackedEnvelope]:
        entry = await self._tracker_store.get(envelope_id)
        return entry

    async def list_pending(self) -> list[TrackedEnvelope]:
        all_entries = await self._tracker_store.list()
        pending = [entry for entry in all_entries.values() if entry.status == EnvelopeStatus.PENDING]
        return pending

    async def cleanup(self) -> None:
        # Cancel all timers
        async with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()

            # Cancel all ack futures
            for future in self._ack_futures.values():
                if not future.done():
                    future.cancel()
            self._ack_futures.clear()

            # Cancel all reply futures
            for future in self._reply_futures.values():
                if not future.done():
                    future.cancel()
            self._reply_futures.clear()

            for q in self._stream_queues.values():
                # signal end to any iterators
                await q.put(_STREAM_END)

            self._stream_queues.clear()

            for ev in self._stream_done.values():
                ev.set()

            self._stream_done.clear()

            self._correlation_to_envelope.clear()

        # Wait for timers to complete
        for timer in timers:
            timer.cancel()
            try:
                await timer
            except asyncio.CancelledError:
                pass

        logger.debug("tracker_cleanup_completed")

    async def recover_pending(self) -> None:
        """Recover pending envelopes and reschedule timers."""
        pending = await self.list_pending()
        logger.debug("tracker_recovering_pending", count=len(pending))

        async with self._lock:
            # Rebuild correlation mapping
            for tracked in pending:
                # Recreate ack future if needed
                if tracked.expected_response_type & FameResponseType.ACK:
                    self._ack_futures[tracked.envelope_id] = asyncio.get_running_loop().create_future()

                # Recreate reply future if needed
                if tracked.expected_response_type & FameResponseType.REPLY:
                    if tracked.corr_id:
                        self._correlation_to_envelope[tracked.corr_id] = tracked.envelope_id
                    self._reply_futures[tracked.envelope_id] = asyncio.get_running_loop().create_future()

                if tracked.expected_response_type & FameResponseType.STREAM:
                    if tracked.corr_id:
                        self._correlation_to_envelope[tracked.corr_id] = tracked.envelope_id
                    self._stream_queues[tracked.envelope_id] = asyncio.Queue()
                    self._stream_done[tracked.envelope_id] = asyncio.Event()

        # Reschedule timers (no retry policy on recovery)
        for tracked in pending:
            await self._schedule_timer(tracked, retry_policy=None, retry_handler=None)

        logger.debug("tracker_recovery_completed", count=len(pending))

    async def _schedule_timer(
        self,
        tracked: TrackedEnvelope,
        retry_policy: Optional[RetryPolicy],
        retry_handler: Optional[RetryEventHandler] = None,
    ) -> None:
        """Schedule a timeout/retry timer for an envelope."""
        async with self._lock:
            # Cancel existing timer
            existing_timer = self._timers.get(tracked.envelope_id)
            if existing_timer:
                existing_timer.cancel()

            async def _timer():
                try:
                    now_ms = int(time.time() * 1000)

                    # Determine what happens first: retry or overall timeout
                    next_retry_at_ms = tracked.timeout_at_ms
                    overall_timeout_at_ms = tracked.overall_timeout_at_ms

                    if next_retry_at_ms <= overall_timeout_at_ms:
                        # Wait for retry/first timeout
                        delay_ms = max(0, next_retry_at_ms - now_ms)
                    else:
                        # Wait for overall timeout
                        delay_ms = max(0, overall_timeout_at_ms - now_ms)

                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000.0)

                    # Check current status
                    entry = await self._tracker_store.get(tracked.envelope_id)
                    if not entry or entry.status != EnvelopeStatus.PENDING:
                        return

                    current_tracked = entry
                    now_ms = int(time.time() * 1000)

                    # Check if we've exceeded the overall timeout
                    if now_ms >= current_tracked.overall_timeout_at_ms:
                        # Overall timeout - no more retries
                        current_tracked.status = EnvelopeStatus.TIMED_OUT
                        await self._tracker_store.set(tracked.envelope_id, current_tracked)

                        # Cancel futures
                        async with self._lock:
                            future = self._ack_futures.pop(tracked.envelope_id, None)
                            logger.debug(
                                "tracker_popped_ack_future_on_timeout",
                                envp_id=entry.envelope_id,
                                future_exists=future is not None,
                            )
                        if future and not future.done():
                            future.set_exception(asyncio.TimeoutError())

                        async with self._lock:
                            reply_future = self._reply_futures.pop(tracked.envelope_id, None)
                        if reply_future and not reply_future.done():
                            reply_future.set_exception(asyncio.TimeoutError())

                        # Notify event handlers
                        for event_handler in self._event_handlers:
                            await event_handler.on_envelope_timeout(current_tracked)

                        logger.debug("tracker_envelope_timed_out", envp_id=tracked.envelope_id)

                    elif retry_policy and current_tracked.attempt < retry_policy.max_retries:
                        # Schedule retry
                        current_tracked.attempt += 1
                        next_delay_ms = retry_policy.next_delay_ms(current_tracked.attempt)

                        # Set next retry time, but don't exceed overall timeout
                        next_retry_time = now_ms + next_delay_ms
                        if next_retry_time <= current_tracked.overall_timeout_at_ms:
                            current_tracked.timeout_at_ms = next_retry_time
                        else:
                            # Next retry would exceed overall timeout, so schedule final timeout instead
                            current_tracked.timeout_at_ms = current_tracked.overall_timeout_at_ms

                        # Update storage
                        await self._tracker_store.set(tracked.envelope_id, current_tracked)

                        # Notify retry handler
                        if retry_handler and current_tracked.original_envelope:
                            await retry_handler.on_retry_needed(
                                current_tracked.original_envelope, current_tracked.attempt, next_delay_ms
                            )

                        # Reschedule timer
                        await self._schedule_timer(current_tracked, retry_policy, retry_handler)

                        logger.debug(
                            "envelope_delivery_retry_scheduled",
                            envp_id=tracked.envelope_id,
                            attempt=current_tracked.attempt,
                            max_retries=retry_policy.max_retries,
                            next_delay_ms=next_delay_ms,
                        )
                    else:
                        # No more retries available - timeout
                        current_tracked.status = EnvelopeStatus.TIMED_OUT
                        await self._tracker_store.set(tracked.envelope_id, current_tracked)

                        # Cancel futures
                        async with self._lock:
                            future = self._ack_futures.pop(tracked.envelope_id, None)
                        if future and not future.done():
                            future.set_exception(asyncio.TimeoutError())

                        async with self._lock:
                            reply_future = self._reply_futures.pop(tracked.envelope_id, None)
                        if reply_future and not reply_future.done():
                            reply_future.set_exception(asyncio.TimeoutError())

                        # Notify event handlers
                        for event_handler in self._event_handlers:
                            await event_handler.on_envelope_timeout(current_tracked)

                        logger.debug("tracker_envelope_timed_out", envp_id=tracked.envelope_id)

                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.error("tracker_timer_error", envp_id=tracked.envelope_id, error=str(e))

            task = self.spawn(_timer(), name=f"tracker-{tracked.envelope_id}")
            self._timers[tracked.envelope_id] = task

    async def _clear_timer(self, envelope_id: str) -> None:
        """Cancel and remove a timer for an envelope."""
        async with self._lock:
            timer = self._timers.pop(envelope_id, None)

        if timer:
            timer.cancel()
            try:
                await timer
            except asyncio.CancelledError:
                pass
