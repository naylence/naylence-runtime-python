"""flow_controller.py - credit window management with cooperative back-pressure.

This version restores the *original* test-driven semantics while still
preventing notifier task spam:

* **add_credits**
  * accepts *any* integer `delta` (positive or negative) and clamps the
    resulting balance between 0 and `initial_window`.
  * When called outside an event-loop (e.g. synchronous unit-tests), the
    credit balance is updated but waiter notification is skipped instead of
    raising *RuntimeError*.
* **consume**
  * clamps at zero rather than raising on under-flow, matching historical
    behaviour.
* **_wake_waiters**
  * debounces the `notify_all()` coroutine as before *but* quietly returns
    when no running loop is active.

The race-safety we introduced earlier is preserved - we still use a per-flow
``asyncio.Condition`` and ensure at most one notifier coroutine exists for a
flow at any time.
"""

from __future__ import annotations

import asyncio
from typing import Dict, Set, Tuple

from naylence.fame.core import FlowFlags


class FlowController:
    """Sliding-window flow/credit accounting for *one* local endpoint.

    A *flow* is identified by a caller-chosen string ``flow_id``.  Each flow
    starts with ``initial_window`` credits.  Sending an envelope *consumes*
    one credit; the peer replenishes credits via an "ACK/CreditUpdate"
    envelope.  When credits reach 0 local senders block in
    :py:meth:`acquire` until more arrive.

    The controller is **event-loop safe** - multiple coroutines can call
    :py:meth:`add_credits`, :py:meth:`consume`, and :py:meth:`acquire` without
    additional locks - but it is **not** thread-safe.
    """

    def __init__(self, initial_window: int, low_watermark_ratio: float = 0.25):
        if initial_window <= 0:
            raise ValueError("initial_window must be > 0")

        self.initial_window = initial_window
        # self.low_watermark = max(1, int(initial_window * low_watermark_ratio))
        self.low_watermark = int(initial_window * low_watermark_ratio)
        # flow_id → remaining credit count
        self._credits: Dict[str, int] = {}
        # flow_id → per-flow Condition (created lazily)
        self._conds: Dict[str, asyncio.Condition] = {}
        # flow_id → outbound window counter
        self._window_ids: Dict[str, int] = {}
        # flows that must emit RESET|SYN on next envelope
        self._reset_requested: Set[str] = set()

    # ---------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------
    def _ensure_flow(self, flow_id: str) -> None:
        """Lazily create bookkeeping structures for *flow_id*."""
        self._credits.setdefault(flow_id, self.initial_window)
        self._conds.setdefault(flow_id, asyncio.Condition())

    def _wake_waiters(self, flow_id: str) -> None:
        """Wake every coroutine blocked in :py:meth:`acquire` for *flow_id*.

        We debounce - at most **one** notifier coroutine per flow can be alive.
        If ``FlowController`` is used in synchronous code with no running loop
        we silently skip the wake-up because nothing could be awaiting anyway.
        """
        cond = self._conds[flow_id]
        existing = getattr(cond, "_waiter_notifier", None)
        if existing and not existing.done():  # already scheduled
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # invoked from sync context - skip notification
            return

        async def _notifier() -> None:
            try:
                async with cond:
                    cond.notify_all()
            finally:
                # Always clear the reference, even on cancellation/error
                setattr(cond, "_waiter_notifier", None)

        # Shield so that cancelling *this* coroutine does not interrupt
        # the notifier once it has been spawned.
        task = loop.create_task(_notifier(), name=f"flow-notifier[{flow_id}]")
        setattr(cond, "_waiter_notifier", asyncio.shield(task))

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def get_credits(self, flow_id: str) -> int:
        """Return the current credit balance for *flow_id*."""
        self._ensure_flow(flow_id)
        return self._credits[flow_id]

    def add_credits(self, flow_id: str, delta: int) -> int:
        """Add ``delta`` credits (positive *or* negative) to *flow_id*.

        The balance is bounded between 0 and ``initial_window``. Returns the new balance.
        If the balance transitions from ``<=0`` to ``>0`` we wake blocked
        acquirers.
        """
        self._ensure_flow(flow_id)
        prev = self._credits[flow_id]
        # clamp into [0, initial_window]
        new_balance = max(0, min(self.initial_window, prev + delta))
        self._credits[flow_id] = new_balance

        # wake waiters only if we crossed the zero boundary
        if prev <= 0 < new_balance:
            self._wake_waiters(flow_id)
        return new_balance

    async def acquire(self, flow_id: str) -> None:
        """Block until at least one credit is available, then consume it."""
        self._ensure_flow(flow_id)
        cond = self._conds[flow_id]
        async with cond:
            while self._credits[flow_id] <= 0:
                await cond.wait()
            self._credits[flow_id] -= 1

    def consume(self, flow_id: str, credits: int = 1) -> int:
        """Consume *credits* immediately (non-blocking).

        If *credits* exceeds the current balance we clamp to **zero** (legacy
        behaviour retained for existing tests).
        Returns the remaining balance.
        """
        if credits < 0:
            raise ValueError("credits must be positive")

        if credits == 0:
            return self._credits.get(flow_id, self.initial_window)

        self._ensure_flow(flow_id)
        remaining = max(self._credits[flow_id] - credits, 0)
        self._credits[flow_id] = remaining
        return remaining

    def needs_refill(self, flow_id: str) -> bool:
        """Return :pydata:`True` if balance is at or below low-watermark."""
        return self.get_credits(flow_id) <= self.low_watermark

    # ---------------------------------------------------------------
    # flow-state (RESET / sequence) helpers
    # ---------------------------------------------------------------
    def reset_flow(self, flow_id: str) -> None:
        """Prepare a *RESET|SYN* flag for the next outbound envelope."""
        self._ensure_flow(flow_id)
        self._reset_requested.add(flow_id)
        self._window_ids.pop(flow_id, None)
        self._credits[flow_id] = self.initial_window
        self._wake_waiters(flow_id)

    def next_window(self, flow_id: str) -> Tuple[int, FlowFlags]:
        """Return ``(window_id, flags)`` for the next outbound envelope."""
        # RESET requested - emit RESET|SYN (window 0)
        if flow_id in self._reset_requested:
            self._reset_requested.remove(flow_id)
            self._window_ids[flow_id] = 0
            return 0, FlowFlags.RESET | FlowFlags.SYN

        # brand-new flow - start at window 0, emit SYN
        if flow_id not in self._window_ids:
            self._window_ids[flow_id] = 0
            return 0, FlowFlags.SYN

        # subsequent envelope - increment window id
        self._window_ids[flow_id] += 1
        return self._window_ids[flow_id], FlowFlags.NONE
