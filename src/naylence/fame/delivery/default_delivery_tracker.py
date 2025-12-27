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
from typing import Any, AsyncIterator, Callable, Dict, Optional

from naylence.fame.core import (
    DeliveryAckFrame,
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    generate_id,
)
from naylence.fame.delivery.delivery_tracker import (
    DeliveryTracker,
    EnvelopeStatus,
    MailboxType,
    TrackedEnvelope,
)
from naylence.fame.delivery.retry_event_handler import RetryEventHandler
from naylence.fame.delivery.retry_policy import RetryPolicy
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.storage.storage_provider import StorageProvider
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
        storage_provider: StorageProvider,
        # *,
        # retry_handler: Optional[RetryEventHandler] = None,
        futures_gc_grace_secs: int = 120,
        futures_sweep_interval_secs: int = 30,
    ) -> None:
        NodeEventListener.__init__(self)
        DeliveryTracker.__init__(self)
        TaskSpawner.__init__(self)
        self._storage_provider = storage_provider

        self._outbox: Optional[KeyValueStore[TrackedEnvelope]] = None

        self._inbox: Optional[KeyValueStore[TrackedEnvelope]] = None

        # corr_id -> envelope_id, use for replies only, not for ACKs
        self._correlation_to_envelope: dict[str, str] = {}

        self._timers: dict[str, asyncio.Task] = {}

        self._ack_futures: dict[str, asyncio.Future[FameEnvelope]] = {}
        self._reply_futures: dict[str, asyncio.Future[FameEnvelope]] = {}

        # GC bookkeeping for completed futures
        self._ack_done_since: dict[str, float] = {}
        self._reply_done_since: dict[str, float] = {}
        self._fut_gc_grace_secs = max(0, int(futures_gc_grace_secs))
        self._fut_sweep_interval_secs = max(1, int(futures_sweep_interval_secs))
        self._shutdown_event = asyncio.Event()

        self._stream_queues: dict[str, asyncio.Queue[Any]] = {}
        self._stream_done: dict[str, asyncio.Event] = {}

        # Dead-letter queue for inbound failures
        self._inbox_dlq: Optional[KeyValueStore[TrackedEnvelope]] = None

        self._lock = asyncio.Lock()
        self._node: NodeLike | None = None
        logger.debug("created_default_delivery_tracker")

    async def on_node_initialized(self, node: NodeLike) -> None:
        self._node = node
        self._outbox = await self._storage_provider.get_kv_store(
            model_cls=TrackedEnvelope,
            namespace="__delivery_outbox",
        )

        self._inbox = await self._storage_provider.get_kv_store(
            model_cls=TrackedEnvelope,
            namespace="__delivery_inbox",
        )

        # Initialize DLQ store for inbound envelopes
        self._inbox_dlq = await self._storage_provider.get_kv_store(
            model_cls=TrackedEnvelope,
            namespace="__delivery_inbox_dlq",
        )

    async def on_node_started(self, node: NodeLike) -> None:
        self._node = node
        # Start futures sweeper
        self.spawn(self._sweep_futures(), name="tracker-futures-sweeper")

    async def on_node_preparing_to_stop(self, node: NodeLike) -> None:
        """Wait for pending acknowledgments until their timeouts expire before node stops."""
        await self._wait_for_pending_acks()

    async def on_node_stopped(self, node: NodeLike) -> None:
        await self.cleanup()
        await self.shutdown_tasks()

    async def _wait_for_pending_acks(self) -> None:
        """Wait for pending acknowledgments until their timeouts expire."""
        logger.debug("tracker_node_preparing_to_stop_waiting_for_pending_acks")

        assert self._outbox

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
                tracked = await self._outbox.get(envelope_id)
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
                        await self._outbox.delete(envelope_id)
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
        self, inbox_name: str, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> Optional[TrackedEnvelope]:
        logger.debug(
            "envelope_delivered",
            envp_id=envelope.id,
            corr_id=envelope.corr_id,
            rtype=FameResponseType(envelope.rtype) if envelope.rtype else FameResponseType.NONE,
            frame_type=type(envelope.frame).__name__,
        )

        assert self._outbox

        if not envelope.corr_id:
            logger.debug("envelope_delivered_no_corr_id", envelope_id=envelope.id)  # type: ignore
            return None

        if isinstance(envelope.frame, DeliveryAckFrame):
            # Ack handling
            if not envelope.frame.ref_id:
                logger.debug("envelope_delivered_no_ref_id", envelope_id=envelope.id)
                return

            if envelope.frame.ok:
                await self.on_ack(envelope, context)
            else:
                await self.on_nack(envelope, context)

        elif envelope.corr_id:
            return await self.on_correlated_message(inbox_name, envelope, context)

        return None

    async def on_envelope_handled(
        self, envelope: TrackedEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None:
        assert self._inbox
        # Set status to HANDLED for consistency
        envelope.status = EnvelopeStatus.HANDLED
        # Delete the envelope from inbox to prevent growth
        # Note: This is the new behavior to prevent inbox from growing indefinitely
        await self._inbox.delete(envelope.original_envelope.id)

    async def on_envelope_handle_failed(
        self,
        inbox_name: str,
        envelope: TrackedEnvelope,
        context: Optional[FameDeliveryContext] = None,
        error: Optional[Exception] = None,
        is_final_failure: bool = False,
    ) -> None:
        """
        Handle the case where envelope handling failed.
        This is called on every retry iteration, not just the final failure.
        Only sets FAILED_TO_HANDLE status if is_final_failure is True.
        """
        assert self._inbox

        # Add failure metadata without changing status (unless final failure)
        if error:
            envelope.meta[f"failure_attempt_{envelope.attempt}_reason"] = str(error)
            envelope.meta[f"failure_attempt_{envelope.attempt}_type"] = type(error).__name__
            envelope.meta["last_failure_reason"] = str(error)
            envelope.meta["last_failure_type"] = type(error).__name__

        if is_final_failure:
            envelope.status = EnvelopeStatus.FAILED_TO_HANDLE
            logger.error(
                "envelope_handle_failed_final",
                inbox_name=inbox_name,
                envp_id=envelope.original_envelope.id,
                error=str(error) if error else "unknown",
                status=envelope.status.name,
                total_attempts=envelope.attempt,
            )
            # Move to DLQ and remove from inbox
            await self.add_to_inbox_dlq(envelope, reason=str(error) if error else None)
            # Ensure it is no longer present in the active inbox
            await self._inbox.delete(envelope.original_envelope.id)
            return
        else:
            logger.warning(
                "envelope_handle_failed_retry",
                inbox_name=inbox_name,
                envp_id=envelope.original_envelope.id,
                error=str(error) if error else "unknown",
                attempt=envelope.attempt,
            )
            # Persist intermediate failure state so recovery can resume correctly
            await self._inbox.set(envelope.original_envelope.id, envelope)

    async def update_tracked_envelope(self, envelope: TrackedEnvelope) -> None:
        """Update a tracked envelope in persistent storage."""
        if envelope.mailbox_type == MailboxType.INBOX:
            assert self._inbox
            await self._inbox.update(envelope.original_envelope.id, envelope)
        elif envelope.mailbox_type == MailboxType.OUTBOX:
            raise RuntimeError(
                f"Updating tracked envelopes of mailbox type {MailboxType.OUTBOX} is not supported"
            )
        else:
            # Fallback for backwards compatibility - assume it's in inbox if mailbox_type is None
            assert self._inbox
            await self._inbox.update(envelope.original_envelope.id, envelope)

    async def _send_ack(self, envelope: FameEnvelope) -> None:
        assert self._node is not None

        if envelope.reply_to is None:
            logger.error("cannot_send_ack_no_reply_to", envp_id=envelope.id)
            return

        if envelope.corr_id is None:
            logger.error("cannot_send_ack_no_corr_id", envp_id=envelope.id)
            return

        logger.debug(
            "tracker_sending_ack", ref_id=envelope.id, to=envelope.reply_to, corr_id=envelope.corr_id
        )

        ack_env = self._node.envelope_factory.create_envelope(
            to=envelope.reply_to,
            frame=DeliveryAckFrame(ok=True, ref_id=envelope.id),
            corr_id=envelope.corr_id,
            trace_id=envelope.trace_id,
        )

        # Uncomment to simulate delayed ACK sending
        # async def delayed_send():
        #     assert self._node
        #     await asyncio.sleep(0.5)
        #     await self._node.send(ack_env)
        # asyncio.create_task(delayed_send())

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
        assert self._outbox

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

        # Overall timeout is a hard cap; do not extend beyond timeout_ms
        overall_timeout_ms = timeout_ms

        # Determine the first timer checkpoint:
        # - With a retry policy, schedule the first retry callback at its first delay
        # - Without a retry policy, the next checkpoint is the overall timeout
        if retry_policy and retry_policy.max_retries > 0:
            try:
                first_delay_ms = max(0, int(retry_policy.next_delay_ms(1)))
            except Exception:
                first_delay_ms = 0
            first_checkpoint_ms = min(overall_timeout_ms, first_delay_ms)
        else:
            first_checkpoint_ms = overall_timeout_ms

        tracked = TrackedEnvelope(
            timeout_at_ms=now_ms + first_checkpoint_ms,
            overall_timeout_at_ms=now_ms + overall_timeout_ms,
            expected_response_type=expected_response_type,
            created_at_ms=now_ms,
            meta=meta or {},
            mailbox_type=MailboxType.OUTBOX,
            original_envelope=envelope,  # Store the envelope directly
        )

        # Persist to storage
        await self._outbox.set(envelope.id, tracked)

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
            future = self._ack_futures.get(envelope_id, None)

        if not future:
            raise RuntimeError(f"No ack expected for envelope {envelope_id}")

        return await self._await_envelope_future(
            envelope_id, FameResponseType.ACK, future, timeout_ms=timeout_ms
        )

    async def await_reply(self, envelope_id: str, *, timeout_ms: Optional[int] = None) -> Any:
        async with self._lock:
            future = self._reply_futures.get(envelope_id)

        if not future:
            raise RuntimeError(f"No reply expected for envelope {envelope_id}")

        return await self._await_envelope_future(
            envelope_id, FameResponseType.REPLY | FameResponseType.STREAM, future, timeout_ms=timeout_ms
        )

    async def _await_envelope_future(
        self,
        envelope_id: str,
        response_type: Any,
        future: asyncio.Future[FameEnvelope],
        timeout_ms: Optional[int] = None,
    ) -> FameEnvelope:
        assert self._outbox
        # Use provided timeout or calculate from tracked envelope
        if timeout_ms is None:
            # Try to get the envelope's configured timeout
            tracked = await self._outbox.get(envelope_id)
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
            raise asyncio.TimeoutError(
                f"Timeout waiting for response_type({response_type}) for envelope {envelope_id}"
            )

        return result

    async def on_ack(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        assert isinstance(envelope.frame, DeliveryAckFrame), "Ack must be from a DeliveryAckFrame"
        assert envelope.corr_id, "Reply envelope must have a correlation ID"
        assert envelope.frame.ref_id, "Ack frame must have a reference ID"
        assert self._outbox

        logger.debug(
            "tracker_on_ack", envp_id=envelope.id, corr_id=envelope.corr_id, ref_id=envelope.frame.ref_id
        )

        tracked_envelope = await self._outbox.get(envelope.frame.ref_id)

        if not tracked_envelope:
            logger.debug("tracker_ack_for_unknown_envelope", envp_id=envelope.id)
            return

        if tracked_envelope.original_envelope.corr_id != envelope.corr_id:
            logger.debug(
                "tracker_ack_corr_id_mismatch",
                envp_id=envelope.id,
                expected_corr_id=tracked_envelope.original_envelope.corr_id,
                actual_corr_id=envelope.corr_id,
            )
            return

        if tracked_envelope.original_envelope.id == envelope.id:
            # Received the original envelope instead of an ack, happens in local-to-local calls
            return

        # Update status
        tracked_envelope.status = (
            EnvelopeStatus.ACKED
            if not (tracked_envelope.expected_response_type & FameResponseType.STREAM)
            else tracked_envelope.status
        )
        await self._outbox.set(tracked_envelope.original_envelope.id, tracked_envelope)

        # Resolve ack future (idempotent) and mark for GC
        async with self._lock:
            future = self._ack_futures.get(tracked_envelope.original_envelope.id, None)
        if future and not future.done():
            future.set_result(envelope)
        await self._mark_done_since(
            self._ack_futures, tracked_envelope.original_envelope.id, self._ack_done_since
        )

        # Cancel timer
        await self._clear_timer(tracked_envelope.original_envelope.id)

        # Notify event handler
        for event_handler in self._event_handlers:
            await event_handler.on_envelope_acked(tracked_envelope)

        logger.debug("tracker_envelope_acked", envp_id=tracked_envelope.original_envelope.id)

    async def on_nack(self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None) -> None:
        assert isinstance(envelope.frame, DeliveryAckFrame), "Nack must be from a DeliveryAckFrame"
        assert envelope.corr_id, "Reply envelope must have a correlation ID"
        assert envelope.frame.ref_id, "Ack frame must have a reference ID"
        assert self._outbox

        tracked_envelope = await self._outbox.get(envelope.frame.ref_id)

        if not tracked_envelope:
            logger.debug("tracker_nack_for_unknown_envelope", envp_id=envelope.id)
            return

        if tracked_envelope.original_envelope.corr_id != envelope.corr_id:
            logger.debug(
                "tracker_nack_corr_id_mismatch",
                envp_id=envelope.id,
                expected_corr_id=tracked_envelope.original_envelope.corr_id,
                actual_corr_id=envelope.corr_id,
            )
            return

        # Update status and metadata
        tracked_envelope.status = EnvelopeStatus.NACKED
        if envelope.frame.reason:
            tracked_envelope.meta["nack_reason"] = envelope.frame.reason

        await self._outbox.set(tracked_envelope.original_envelope.id, tracked_envelope)

        # Resolve ack and reply futures with error (idempotent) and mark for GC
        nack_error = RuntimeError(f"Envelope nacked: {envelope.frame.reason or 'unknown'}")
        async with self._lock:
            ack_future = self._ack_futures.get(tracked_envelope.original_envelope.id, None)
            reply_future = self._reply_futures.get(tracked_envelope.original_envelope.id, None)

        if ack_future and not ack_future.done():
            ack_future.set_exception(nack_error)
        if reply_future and not reply_future.done():
            reply_future.set_exception(nack_error)

        await self._mark_done_since(
            self._ack_futures, tracked_envelope.original_envelope.id, self._ack_done_since
        )
        await self._mark_done_since(
            self._reply_futures, tracked_envelope.original_envelope.id, self._reply_done_since
        )

        stream_queue = self._stream_queues.get(tracked_envelope.original_envelope.id)
        if stream_queue:
            await stream_queue.put(envelope)
            await stream_queue.put(_STREAM_END)
            ev = self._stream_done.get(tracked_envelope.original_envelope.id)
            if ev:
                ev.set()

        # Cancel timer
        await self._clear_timer(tracked_envelope.original_envelope.id)

        # Notify event handler
        for event_handler in self._event_handlers:
            await event_handler.on_envelope_nacked(tracked_envelope, envelope.frame.reason)

        logger.debug(
            "tracker_envelope_nacked",
            envp_id=tracked_envelope.original_envelope.id,
            reason=envelope.frame.reason,
        )

    async def on_correlated_message(
        self, inbox_name: str, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> Optional[TrackedEnvelope]:
        assert envelope.corr_id, "Envelope must have a correlation ID"
        assert self._outbox

        async with self._lock:
            tracked_envelope_id = self._correlation_to_envelope.get(envelope.corr_id)

        if (
            tracked_envelope_id is not None
            and (tracked_envelope := await self._outbox.get(tracked_envelope_id))
            and tracked_envelope.original_envelope.id != envelope.id
        ):
            tracked_envelope = await self.on_reply(envelope, tracked_envelope, context)
        else:
            assert self._inbox

            tracked_envelope = await self._inbox.get(envelope.id)
            if tracked_envelope is not None:
                if tracked_envelope.status != EnvelopeStatus.HANDLED:
                    tracked_envelope.status = EnvelopeStatus.RECEIVED
                    await self._inbox.set(envelope.id, tracked_envelope)
                else:
                    logger.debug(
                        "tracker_duplicate_envelope_already_handled",
                        envp_id=envelope.id,
                        status=tracked_envelope.status.name,
                    )
            else:
                tracked_envelope = TrackedEnvelope(
                    timeout_at_ms=0,
                    overall_timeout_at_ms=0,
                    expected_response_type=envelope.rtype or FameResponseType.NONE,
                    created_at_ms=int(time.time() * 1000),
                    status=EnvelopeStatus.RECEIVED,
                    mailbox_type=MailboxType.INBOX,
                    original_envelope=envelope,
                    service_name=inbox_name,
                )

                await self._inbox.set(envelope.id, tracked_envelope)

        # When reply itself requires an ack, send it
        if envelope.rtype and bool(envelope.rtype & FameResponseType.ACK):
            await self._send_ack(envelope)

        return tracked_envelope

    async def on_reply(
        self,
        envelope: FameEnvelope,
        tracked_envelope: TrackedEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> TrackedEnvelope:
        assert self._node is not None
        assert envelope.corr_id, "Reply envelope must have a correlation ID"
        assert self._outbox
        assert tracked_envelope.original_envelope.id != envelope.id

        if tracked_envelope.expected_response_type & FameResponseType.STREAM:
            # Treat as stream item for metrics only; upstream handles delivery
            await self.on_stream_item(tracked_envelope.original_envelope.id, envelope)
            return tracked_envelope

        # Update status
        tracked_envelope.status = EnvelopeStatus.RESPONDED
        await self._outbox.set(tracked_envelope.original_envelope.id, tracked_envelope)

        # Cancel timer
        await self._clear_timer(tracked_envelope.original_envelope.id)

        # Resolve reply/ack futures (idempotent) and mark for GC
        async with self._lock:
            reply_future = self._reply_futures.get(tracked_envelope.original_envelope.id, None)
            ack_future = self._ack_futures.get(tracked_envelope.original_envelope.id, None)

        if reply_future and not reply_future.done():
            reply_future.set_result(envelope)
        await self._mark_done_since(
            self._reply_futures, tracked_envelope.original_envelope.id, self._reply_done_since
        )

        if ack_future and not ack_future.done():
            ack_env = self._node.envelope_factory.create_envelope(
                to=envelope.reply_to,
                frame=DeliveryAckFrame(
                    ok=True,
                    ref_id=tracked_envelope.original_envelope.id,
                    reason="Auto-ack for reply",
                ),
                corr_id=envelope.corr_id,
                trace_id=envelope.trace_id,
            )
            ack_future.set_result(ack_env)
        await self._mark_done_since(
            self._ack_futures, tracked_envelope.original_envelope.id, self._ack_done_since
        )

        # Notify event handler
        for event_handler in self._event_handlers:
            await event_handler.on_envelope_replied(tracked_envelope, envelope)

        logger.debug(
            "tracked_envelope_replied",
            envp_id=tracked_envelope.original_envelope.id,
            corr_id=envelope.corr_id,
        )
        return tracked_envelope

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
        assert self._outbox
        entry = await self._outbox.get(envelope_id)
        if entry:
            entry.status = EnvelopeStatus.RESPONDED
            await self._outbox.set(envelope_id, entry)
        q = self._stream_queues.get(envelope_id)
        if q:
            await q.put(_STREAM_END)
        ev = self._stream_done.get(envelope_id)
        if ev:
            ev.set()

    async def get_tracked_envelope(self, envelope_id: str) -> Optional[TrackedEnvelope]:
        assert self._outbox
        entry = await self._outbox.get(envelope_id)
        return entry

    async def list_pending(self) -> list[TrackedEnvelope]:
        assert self._outbox
        all_entries = await self._outbox.list()
        pending = [entry for entry in all_entries.values() if entry.status == EnvelopeStatus.PENDING]
        return pending

    async def list_inbound(
        self, filter: Optional[Callable[[TrackedEnvelope], bool]] = None
    ) -> list[TrackedEnvelope]:
        """List inbound envelopes that are in RECEIVED or FAILED_TO_HANDLE status."""
        if not self._inbox:
            # Return empty list if inbox is not initialized yet
            return []
        all_entries = await self._inbox.list()
        failed_inbound = [entry for entry in all_entries.values() if not filter or filter(entry)]
        return failed_inbound

    # Inbox DLQ API
    async def add_to_inbox_dlq(
        self, tracked_envelope: TrackedEnvelope, reason: Optional[str] = None
    ) -> None:
        """
        Put an inbound tracked envelope into the DLQ store and annotate with metadata.
        Keeps the envelope payload for later inspection or manual requeue.
        """
        if not self._inbox_dlq:
            logger.error("dlq_not_initialized", envp_id=tracked_envelope.original_envelope.id)
            return

        # Mark DLQ metadata (do not introduce a new status to avoid breaking consumers)
        tracked_envelope.meta["dlq"] = True
        if reason:
            tracked_envelope.meta["dlq_reason"] = reason
        tracked_envelope.meta["dead_lettered_at_ms"] = int(time.time() * 1000)

        await self._inbox_dlq.set(tracked_envelope.original_envelope.id, tracked_envelope)
        logger.warning(
            "envelope_moved_to_dlq",
            envp_id=tracked_envelope.original_envelope.id,
            service_name=tracked_envelope.service_name,
        )

    async def get_from_inbox_dlq(self, envelope_id: str) -> Optional[TrackedEnvelope]:
        """Get a specific envelope from the inbox DLQ by envelope ID."""
        if not self._inbox_dlq:
            return None
        return await self._inbox_dlq.get(envelope_id)

    async def list_inbox_dlq(self) -> list[TrackedEnvelope]:
        """List all envelopes currently in the inbox DLQ."""
        if not self._inbox_dlq:
            return []
        items = await self._inbox_dlq.list()
        return list(items.values())

    async def purge_inbox_dlq(self, predicate: Optional[Callable[[TrackedEnvelope], bool]] = None) -> int:
        """
        Delete inbox DLQ entries. If a predicate is provided, only delete matching items.
        Returns the number of deleted entries.
        """
        if not self._inbox_dlq:
            return 0
        items = await self._inbox_dlq.list()
        to_delete = [k for k, v in items.items() if (predicate(v) if predicate else True)]
        for key in to_delete:
            await self._inbox_dlq.delete(key)
        if to_delete:
            logger.debug("dlq_purged", count=len(to_delete))
        return len(to_delete)

    async def cleanup(self) -> None:
        # Signal shutdown to wake up the sweeper
        self._shutdown_event.set()

        # Cancel all timers
        async with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()

            # Cancel all ack futures
            for future in self._ack_futures.values():
                if not future.done():
                    future.cancel()
            self._ack_futures.clear()
            self._ack_done_since.clear()

            # Cancel all reply futures
            for future in self._reply_futures.values():
                if not future.done():
                    future.cancel()
            self._reply_futures.clear()
            self._reply_done_since.clear()

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
                    self._ack_futures[tracked.original_envelope.id] = (
                        asyncio.get_running_loop().create_future()
                    )

                # Recreate reply future if needed
                if tracked.expected_response_type & FameResponseType.REPLY:
                    if tracked.original_envelope.corr_id:
                        self._correlation_to_envelope[tracked.original_envelope.corr_id] = (
                            tracked.original_envelope.id
                        )
                    self._reply_futures[tracked.original_envelope.id] = (
                        asyncio.get_running_loop().create_future()
                    )

                if tracked.expected_response_type & FameResponseType.STREAM:
                    if tracked.original_envelope.corr_id:
                        self._correlation_to_envelope[tracked.original_envelope.corr_id] = (
                            tracked.original_envelope.id
                        )
                    self._stream_queues[tracked.original_envelope.id] = asyncio.Queue()
                    self._stream_done[tracked.original_envelope.id] = asyncio.Event()

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
        assert self._outbox

        async with self._lock:
            # Cancel existing timer
            existing_timer = self._timers.get(tracked.original_envelope.id)
            if existing_timer:
                existing_timer.cancel()

            async def _timer():
                assert self._outbox
                assert self._node
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
                    entry = await self._outbox.get(tracked.original_envelope.id)
                    if not entry or entry.status != EnvelopeStatus.PENDING:
                        return

                    current_tracked = entry
                    now_ms = int(time.time() * 1000)

                    # Check if we've exceeded the overall timeout
                    if now_ms >= current_tracked.overall_timeout_at_ms:
                        # Overall timeout - no more retries
                        current_tracked.status = EnvelopeStatus.TIMED_OUT
                        await self._outbox.set(tracked.original_envelope.id, current_tracked)

                        # Cancel futures by completing with TimeoutError (idempotent) and mark for GC
                        async with self._lock:
                            future = self._ack_futures.get(tracked.original_envelope.id, None)
                        if future and not future.done():
                            future.set_exception(asyncio.TimeoutError())
                        await self._mark_done_since(
                            self._ack_futures, tracked.original_envelope.id, self._ack_done_since
                        )

                        async with self._lock:
                            reply_future = self._reply_futures.get(tracked.original_envelope.id, None)
                        if reply_future and not reply_future.done():
                            reply_future.set_exception(asyncio.TimeoutError())
                        await self._mark_done_since(
                            self._reply_futures, tracked.original_envelope.id, self._reply_done_since
                        )

                        # Notify event handlers
                        for event_handler in self._event_handlers:
                            await event_handler.on_envelope_timeout(current_tracked)

                        logger.debug("tracker_envelope_timed_out", envp_id=tracked.original_envelope.id)

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
                        await self._outbox.set(tracked.original_envelope.id, current_tracked)

                        # Notify retry handler
                        if retry_handler and current_tracked.original_envelope:
                            await retry_handler.on_retry_needed(
                                current_tracked.original_envelope,
                                current_tracked.attempt,
                                next_delay_ms,
                                context=FameDeliveryContext(
                                    from_system_id=self._node.id, origin_type=DeliveryOriginType.LOCAL
                                ),
                            )

                        # Reschedule timer
                        await self._schedule_timer(current_tracked, retry_policy, retry_handler)

                        logger.debug(
                            "envelope_delivery_retry_scheduled",
                            envp_id=tracked.original_envelope.id,
                            attempt=current_tracked.attempt,
                            max_retries=retry_policy.max_retries,
                            next_delay_ms=next_delay_ms,
                        )
                    else:
                        # No more retries available; keep waiting until the overall timeout cap
                        if now_ms < current_tracked.overall_timeout_at_ms:
                            current_tracked.timeout_at_ms = current_tracked.overall_timeout_at_ms
                            await self._outbox.set(tracked.original_envelope.id, current_tracked)

                            # Reschedule only to the overall timeout; no further retries will be issued
                            await self._schedule_timer(current_tracked, retry_policy, retry_handler)

                            logger.debug(
                                "envelope_retries_exhausted_waiting_until_overall_timeout",
                                envp_id=tracked.original_envelope.id,
                                attempt=current_tracked.attempt,
                                overall_timeout_at_ms=current_tracked.overall_timeout_at_ms,
                            )
                            return

                        # Fallback: treat as timed out (should normally be handled earlier)
                        current_tracked.status = EnvelopeStatus.TIMED_OUT
                        await self._outbox.set(tracked.original_envelope.id, current_tracked)

                        # Cancel futures by completing with TimeoutError (idempotent) and mark for GC
                        async with self._lock:
                            future = self._ack_futures.get(tracked.original_envelope.id, None)
                        if future and not future.done():
                            future.set_exception(asyncio.TimeoutError())
                        await self._mark_done_since(
                            self._ack_futures, tracked.original_envelope.id, self._ack_done_since
                        )

                        async with self._lock:
                            reply_future = self._reply_futures.get(tracked.original_envelope.id, None)
                        if reply_future and not reply_future.done():
                            reply_future.set_exception(asyncio.TimeoutError())
                        await self._mark_done_since(
                            self._reply_futures, tracked.original_envelope.id, self._reply_done_since
                        )

                        # Notify event handlers
                        for event_handler in self._event_handlers:
                            await event_handler.on_envelope_timeout(current_tracked)

                        logger.debug("tracker_envelope_timed_out", envp_id=tracked.original_envelope.id)

                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.error("tracker_timer_error", envp_id=tracked.original_envelope.id, error=str(e))

            task = self.spawn(_timer(), name=f"tracker-{tracked.original_envelope.id}")
            self._timers[tracked.original_envelope.id] = task

    async def _clear_timer(self, envelope_id: str) -> None:
        """Cancel and remove a timer for an envelope."""
        async with self._lock:
            timer = self._timers.pop(envelope_id, None)

        if timer:
            try:
                timer.cancel()
            except Exception:
                # Ignore exceptions from cancel - timer might be in unexpected state
                pass
            try:
                await timer
            except asyncio.CancelledError:
                pass

    def _status_is_terminal(self, status: EnvelopeStatus) -> bool:
        return status in (
            EnvelopeStatus.ACKED,
            EnvelopeStatus.RESPONDED,
            EnvelopeStatus.TIMED_OUT,
            EnvelopeStatus.NACKED,
        )

    async def _mark_done_since(
        self,
        registry: dict[str, asyncio.Future[Any]],
        env_id: str,
        done_since_map: dict[str, float],
    ) -> None:
        # Only record first done timestamp
        async with self._lock:
            fut = registry.get(env_id)
            if fut and fut.done() and env_id not in done_since_map:
                done_since_map[env_id] = time.time()

    async def _sweep_futures(self) -> None:
        # Periodically sweep completed futures after grace period,
        # only when the tracked envelope is terminal or absent.
        while True:
            try:
                # Wait for either timeout or shutdown signal
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(), timeout=self._fut_sweep_interval_secs
                    )
                    # Shutdown event was set, exit
                    break
                except asyncio.TimeoutError:
                    # Normal timeout, continue with sweep
                    pass

                if not self._outbox:
                    continue

                now = time.time()
                # Snapshot candidates without holding the lock across awaits
                async with self._lock:
                    ack_candidates = [
                        env_id
                        for (env_id, since) in self._ack_done_since.items()
                        if now - since >= self._fut_gc_grace_secs
                    ]
                    reply_candidates = [
                        env_id
                        for (env_id, since) in self._reply_done_since.items()
                        if now - since >= self._fut_gc_grace_secs
                    ]

                # Check terminal state
                def _batch(items: list[str], size: int = 128):
                    for i in range(0, len(items), size):
                        yield items[i : i + size]

                to_remove_ack: list[str] = []
                to_remove_reply: list[str] = []

                # Evaluate ACK candidates
                for batch in _batch(ack_candidates):
                    for env_id in batch:
                        tracked = await self._outbox.get(env_id)
                        if tracked is None or self._status_is_terminal(tracked.status):
                            to_remove_ack.append(env_id)

                # Evaluate REPLY candidates
                for batch in _batch(reply_candidates):
                    for env_id in batch:
                        tracked = await self._outbox.get(env_id)
                        if tracked is None or self._status_is_terminal(tracked.status):
                            to_remove_reply.append(env_id)

                # Remove under lock
                if to_remove_ack or to_remove_reply:
                    async with self._lock:
                        for env_id in to_remove_ack:
                            self._ack_futures.pop(env_id, None)
                            self._ack_done_since.pop(env_id, None)
                        for env_id in to_remove_reply:
                            self._reply_futures.pop(env_id, None)
                            self._reply_done_since.pop(env_id, None)

                    if to_remove_ack or to_remove_reply:
                        logger.debug(
                            "tracker_swept_completed_futures",
                            ack_removed=len(to_remove_ack),
                            reply_removed=len(to_remove_reply),
                            grace_secs=self._fut_gc_grace_secs,
                        )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("tracker_sweeper_error", error=str(e))
