"""
Enhanced BaseAsyncConnector with cleaner shutdown, better back-pressure
reporting, and richer metrics/logging. Maintains **backwards compatibility**
with subclasses that expect the old internal method names.
"""

from __future__ import annotations

import asyncio
import os
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from json import JSONDecodeError
from typing import Any, Optional, Tuple

from pydantic import ValidationError

from naylence.fame.core import (
    ConnectorState,
    CreditUpdateFrame,
    FameChannelMessage,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    FlowFlags,
    create_fame_envelope,
    generate_id,
)
from naylence.fame.errors.errors import FameMessageTooLarge, FameTransportClose
from naylence.fame.util.envelope_context import envelope_context
from naylence.fame.util.formatter import AnsiColor, color, format_timestamp
from naylence.fame.util.logging import getLogger
from naylence.fame.util.metrics_emitter import MetricsEmitter
from naylence.fame.util.task_spawner import TaskSpawner
from naylence.fame.util.util import pretty_model

logger = getLogger(__name__)

ENV_VAR_SHOW_ENVELOPES = "FAME_SHOW_ENVELOPES"
ENV_VAR_FAME_FLOW_CONTROL = "FAME_FLOW_CONTROL"

FLOW_CONTROL_ENABLED = os.getenv(ENV_VAR_FAME_FLOW_CONTROL, "1") != "0"
_STOP_SENTINEL: Any = object()


def _timestamp() -> str:
    return color(format_timestamp(), AnsiColor.GRAY)


class _NoopFlowController:
    """Flow-control stub that behaves as if infinite credits exist."""

    _credits = defaultdict(lambda: 1_000_000)

    async def acquire(self, flow_id: str) -> None:
        return None

    def add_credits(self, flow_id: str, delta: int) -> int:
        return self._credits[flow_id]

    def get_credits(self, flow_id: str) -> int:
        return self._credits[flow_id]

    def consume(self, flow_id: str, credits: int = 1) -> int:
        return self._credits[flow_id]

    def needs_refill(self, flow_id: str) -> bool:
        return False

    def next_window(self, flow_id: str) -> Tuple[int, FlowFlags]:
        return 0, FlowFlags.NONE


FAME_MAX_MESSAGE_SIZE = 1024 * 256


class BaseAsyncConnector(FameConnector, TaskSpawner, ABC):
    """Abstract async transport adapter with optional flow-control."""

    def __init__(
        self,
        *,
        max_queue_size: int = 1_000,
        initial_window: int = 32,
        enqueue_timeout: float = 0.1,
        drain_timeout: float = 1.0,
        flow_control: bool | None = None,
        metrics_emitter: Optional[MetricsEmitter] = None,
    ) -> None:
        TaskSpawner.__init__(self)
        self._enqueue_timeout = enqueue_timeout
        self._drain_timeout = drain_timeout
        self._metrics = metrics_emitter
        self._handler: Optional[FameEnvelopeHandler] = None

        self._send_q: asyncio.Queue[bytes | object] = asyncio.Queue(maxsize=max_queue_size)
        self._send_task: Optional[asyncio.Task[None]] = None
        self._recv_task: Optional[asyncio.Task[None]] = None
        self._closed = asyncio.Event()

        # Initialize connector state
        self._state = ConnectorState.INITIALIZED

        # Initialize diagnostic properties for close tracking
        self._close_code: Optional[int] = None
        self._close_reason: Optional[str] = None

        use_fc = flow_control if flow_control is not None else FLOW_CONTROL_ENABLED
        if use_fc:
            from naylence.fame.channel.flow_controller import FlowController

            self._flow_ctrl = FlowController(initial_window)
            self._fc_enabled = True
        else:
            self._flow_ctrl = _NoopFlowController()  # type: ignore
            self._fc_enabled = False

        self._initial_window = initial_window
        self._connector_flow_id = generate_id()
        self._last_error: Optional[BaseException] = None

    # ---------------------------------------------------------------------
    # State Management
    # ---------------------------------------------------------------------
    @property
    def state(self) -> ConnectorState:
        """Get the current state of the connector.

        Returns:
            A string representing the connector state.
        """
        return self._state

    @property
    def connector_state(self) -> ConnectorState:
        """Get the current state of the connector as an enum.

        Returns:
            The current ConnectorState enum value.
        """
        return self._state

    @property
    def close_code(self) -> Optional[int]:
        """Get the close code if the connector was closed.

        Returns:
            The close code if available, None otherwise.
        """
        return self._close_code

    @property
    def close_reason(self) -> Optional[str]:
        """Get the close reason if the connector was closed.

        Returns:
            The close reason if available, None otherwise.
        """
        return self._close_reason

    @property
    def last_error(self) -> Optional[BaseException]:
        """Get the last error that occurred on the connector.

        Returns:
            The last error if available, None otherwise.
        """
        return self._last_error

    def _set_state(self, new_state: ConnectorState) -> None:
        """Update the connector state and log the transition.

        Args:
            new_state: The new state to transition to.
        """
        if self._state != new_state:
            old_state = self._state
            self._state = new_state
            logger.debug(
                "connector_state_transition",
                connector_id=getattr(self, "_connector_flow_id", "unknown"),
                old_state=old_state.value,
                new_state=new_state.value,
            )

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------
    async def start(self, inbound_handler: FameEnvelopeHandler) -> None:
        if self._handler is not None:
            raise RuntimeError("Connector already started")

        if not self._state.can_start:
            raise RuntimeError(f"Cannot start connector in state: {self._state}")

        self._handler = inbound_handler
        self._send_task = self.spawn(self._send_loop(), name="send-loop")
        # Keep the original public name so subclasses / tests continue to work
        self._recv_task = self.spawn(self._receive_loop(), name="receive-loop")

        self._set_state(ConnectorState.STARTED)

    async def replace_handler(self, handler: FameEnvelopeHandler) -> None:
        self._handler = handler

    async def stop(self) -> None:
        if not self._state.can_stop:
            # Log as debug instead of warning since multiple stop calls are normal
            # during shutdown sequences (e.g., Node.stop() and UpstreamSessionManager cleanup)
            logger.debug(
                "connector_stop_already_stopped",
                current_state=self._state.value,
                connector_id=self._connector_flow_id,
            )
            return

        self._set_state(ConnectorState.STOPPED)
        await self._shutdown(code=1000, reason="normal closure")
        if self._last_error:
            raise self._last_error

    async def close(self, code: Optional[int] = None, reason: Optional[str] = None) -> None:
        """
        Close the connection with optional code and reason.

        Args:
            code: WebSocket close code (defaults to 1000 for normal closure)
            reason: Close reason (defaults to "normal closure")
        """
        if not self._state.can_close:
            logger.warning(
                "connector_close_invalid_state",
                current_state=self._state.value,
                connector_id=self._connector_flow_id,
            )
            return

        self._set_state(ConnectorState.CLOSED)
        await self._shutdown(code=code or 1000, reason=reason or "normal closure")
        if self._last_error:
            raise self._last_error

    async def push_to_receive(self, raw_or_envelope: bytes | FameEnvelope | FameChannelMessage) -> None:
        """Push data to the receive queue for processing.

        This method is a placeholder and should be implemented by subclasses
        to handle incoming data appropriately.
        """
        raise NotImplementedError("Subclasses must implement push_to_receive()")

    async def wait_until_closed(self) -> None:
        await self._closed.wait()

    # ------------------------------------------------------------------
    # Backwards‑compat shim: expose old name used by LoopbackConnector
    # ------------------------------------------------------------------
    async def _receive_loop(self):  # noqa: D401 – imperative alias
        await self._recv_loop()

    # ------------------------------------------------------------------
    # Public send
    # ------------------------------------------------------------------
    async def send(self, envelope: FameEnvelope) -> None:
        if self._closed.is_set():
            raise FameTransportClose(code=1006, reason="Connection closed")

        if self._fc_enabled and not isinstance(envelope.frame, CreditUpdateFrame):
            flow_id = envelope.flow_id or self._connector_flow_id
            envelope.flow_id = flow_id
            t0: float = 0.0
            if self._metrics:
                t0 = time.monotonic()
            await self._flow_ctrl.acquire(flow_id)
            if self._metrics:
                self._metrics.histogram(
                    "connector.acquire_latency",
                    time.monotonic() - t0,
                    {"flow_id": flow_id},
                )
            wnd, flags = self._flow_ctrl.next_window(flow_id)
            envelope.seq_id = wnd
            envelope.flow_flags = (envelope.flow_flags or FlowFlags.NONE) | flags

        raw = envelope.model_dump_json(by_alias=True, exclude_none=True).encode()
        raw_size = len(raw)
        if raw_size > FAME_MAX_MESSAGE_SIZE:
            raise FameMessageTooLarge(f"Message size {raw_size} exceeds maximum {FAME_MAX_MESSAGE_SIZE}")

        try:
            await asyncio.wait_for(self._send_q.put(raw), timeout=self._enqueue_timeout)
        except asyncio.TimeoutError as te:
            from naylence.fame.errors.errors import BackPressureFull

            depth = self._send_q.qsize()
            raise BackPressureFull(reason=f"send-queue full ({depth}/{self._send_q.maxsize})") from te
        if self._metrics:
            self._metrics.gauge(
                "connector.send_queue_depth",
                float(self._send_q.qsize()),
                {"connector": type(self).__name__},
            )

    # ------------------------------------------------------------------
    # Internal loops
    # ------------------------------------------------------------------
    async def _send_loop(self) -> None:
        try:
            while True:
                env_or_stop = await self._send_q.get()
                if env_or_stop is _STOP_SENTINEL:
                    break
                assert isinstance(env_or_stop, (bytes)), f"Expected bytes, got {type(env_or_stop)}"
                await self._transport_send_bytes(env_or_stop)
        except asyncio.CancelledError:
            logger.debug("send_loop_cancelled", loop_name=type(self).__name__)
            raise
        except FameTransportClose as close:
            await self._shutdown(close.code, close.reason, exc=close)
        except Exception as e:
            logger.critical(
                f"unexpected exception in send loop: {e}",
                type(self).__name__,
                exc_info=True,
            )
            raise

    async def _recv_loop(self) -> None:
        if not self._handler:
            raise RuntimeError("Handler not set")
        try:
            while True:
                message = await self._transport_receive()
                message_context: FameDeliveryContext | None = None
                if isinstance(message, FameEnvelope):
                    env = message
                elif isinstance(message, FameChannelMessage):
                    env = message.envelope
                    message_context = message.context
                elif isinstance(message, bytes):
                    try:
                        env = FameEnvelope.model_validate_json(message, by_alias=True)
                    except (JSONDecodeError, ValidationError) as e:
                        logger.error(f"Invalid envelope: {message}, error: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Invalid envelope: {message}, error: {e}")
                        raise
                elif isinstance(message, FameTransportClose):
                    # Transport close - initiate shutdown
                    await self._shutdown_with_error(message, code=message.code, reason=message.reason)
                    return
                else:
                    raise TypeError(
                        f"Expected FameEnvelope, bytes, or FameTransportClose, got {type(message)}"
                    )

                with envelope_context(env):
                    logger.trace(f"connector_received_envelope {pretty_model(env)}\n")
                    if bool(os.getenv(ENV_VAR_SHOW_ENVELOPES) == "true"):
                        print(
                            f"\n{_timestamp()} - {color('Received envelope 📨', AnsiColor.BLUE)}\n{
                                pretty_model(env)
                            }"
                        )
                    if isinstance(env.frame, CreditUpdateFrame):
                        self._flow_ctrl.add_credits(env.frame.flow_id, env.frame.credits)
                        continue
                    await self._handler(env, message_context or FameDeliveryContext(from_connector=self))
                    flow_id = env.flow_id or self._connector_flow_id
                    self._flow_ctrl.consume(flow_id)
                    await self._maybe_emit_credit(flow_id, env.trace_id)
        except asyncio.CancelledError:
            logger.debug("recv_loop_cancelled", name=type(self).__name__)
            raise
        except FameTransportClose as close:
            await self._shutdown(close.code, close.reason, exc=close)
        except Exception:
            logger.critical(
                "unexpected_error_in recv_loop",
                exc_info=True,
            )
            raise

    # ------------------------------------------------------------------
    # Credit helpers
    # ------------------------------------------------------------------
    async def _maybe_emit_credit(self, flow_id: str, trace_id: Optional[str] = None) -> None:
        if not self._flow_ctrl.needs_refill(flow_id):
            return
        delta = self._initial_window
        self._flow_ctrl.add_credits(flow_id, delta)
        ack_env = create_fame_envelope(
            trace_id=trace_id,
            flow_id=flow_id,
            window_id=0,
            frame=CreditUpdateFrame(flow_id=flow_id, credits=delta),
            flags=FlowFlags.ACK,
        )
        await self.send(ack_env)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    async def _shutdown_with_error(
        self,
        exc: BaseException,
        code: int = 1006,
        reason: Optional[str] = None,
    ) -> None:
        """Shutdown the connector due to an error.

        Args:
            exc: The exception that caused the shutdown
            code: Close code (defaults to 1006 for abnormal closure)
            reason: Close reason (defaults to error message)
        """
        error_reason = reason or f"{type(exc).__name__}: {str(exc)}"
        await self._shutdown(code=code, reason=error_reason, exc=exc)

    async def _shutdown(
        self,
        code: int,
        reason: str,
        grace_period: float = 2.0,
        join_timeout: float = 1.0,
        exc: Optional[BaseException] = None,
    ) -> None:
        if self._closed.is_set():
            return
        self._closed.set()

        # Capture diagnostic information
        self._close_code = code
        self._close_reason = reason
        if exc:
            self._last_error = exc

        # Set state to closed only if we're not already stopped
        # (since stop() already sets STOPPED state)
        if self._state not in (ConnectorState.STOPPED, ConnectorState.CLOSED):
            self._set_state(ConnectorState.CLOSED)

        try:
            self._send_q.put_nowait(_STOP_SENTINEL)
        except asyncio.QueueFull:
            if self._send_task:
                self._send_task.cancel()

        await self._transport_close(code, reason)

        # ── 3. Await both tasks deterministically ───────────────────────
        tasks = {self._send_task, self._recv_task}
        done, pending = await asyncio.wait(tasks, timeout=grace_period)  # type: ignore

        await self.shutdown_tasks(grace_period=grace_period, join_timeout=join_timeout)

        if pending:
            for t in pending:
                t.cancel()
                try:
                    await asyncio.wait_for(t, timeout=join_timeout)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    logger.warning(
                        "task_did_not_shutdown",
                        task_name=t.get_name(),
                        join_timeout=join_timeout,
                    )
                except Exception as exc:
                    # Handle known WebSocket shutdown race condition
                    # (this is expected during normal shutdown)
                    if "await wasn't used with future" in str(exc):
                        logger.debug(
                            "task_shutdown_completed_with_known_race_condition",
                            task_name=t.get_name(),
                            note="WebSocket closed during receive operation (normal)",
                        )
                    else:
                        logger.error(
                            "task %s raised during shutdown: %s",
                            t.get_name(),
                            exc,
                            exc_info=True,
                        )

        if self._last_error:
            raise self._last_error

        if self.last_spawner_error:
            raise self.last_spawner_error

    # ------------------------------------------------------------------
    # Transport contracts
    # ------------------------------------------------------------------

    @abstractmethod
    async def _transport_send_bytes(self, data: bytes) -> None: ...

    @abstractmethod
    async def _transport_receive(self) -> bytes | FameEnvelope | FameChannelMessage: ...

    async def _transport_close(self, code: int, reason: str) -> None: ...
