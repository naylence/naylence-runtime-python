from __future__ import annotations

import asyncio
import contextvars
from typing import Any, Coroutine, Optional, Set

from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class TaskSpawner:
    def __init__(self, *args, **kwargs):
        # we don’t capture context here
        self._tasks: Set[asyncio.Task] = set()
        self._last_spawner_error: Optional[BaseException] = None  # first non-cancel exception

    def spawn(self, coro: Coroutine[Any, Any, Any], *, name: Optional[str] = None) -> asyncio.Task:
        logger.debug("starting_background_task", task_name=name)
        # capture the *current* context right at spawn() time
        ctx = contextvars.copy_context()

        # schedule task creation inside that context:
        def _make_task():
            return asyncio.create_task(coro, name=name)

        task: asyncio.Task = ctx.run(_make_task)
        self._tasks.add(task)

        # attach richer done-callback that records exceptions
        def _on_done(t: asyncio.Task):
            self._tasks.discard(t)

            # If the task itself was cancelled we're done
            if t.cancelled():
                return

            # Try to obtain the real exception (can raise CancelledError again)
            try:
                exc = t.exception()
            except asyncio.CancelledError:
                return
            if exc is None:
                return

            # ── dump *everything* about the exception for troubleshooting ──────
            logger.debug(
                "task_done_debug",
                task_name=t.get_name(),
                exc_class=exc.__class__.__name__,
                exc_message=str(exc),
            )

            # ── handle known WebSocket shutdown race condition ─────────────────
            if "await wasn't used with future" in str(exc):
                logger.debug(
                    "task_shutdown_race_condition_handled",
                    task_name=t.get_name(),
                    note="Normal WebSocket close timing during shutdown - not an error",
                )
                return  # NOT fatal - this is expected during shutdown

            # ── handle normal WebSocket closure ─────────────────────────────────
            from naylence.fame.errors.errors import FameTransportClose

            if isinstance(exc, FameTransportClose):
                # Check if this is a normal closure (code 1000) or other expected codes
                if (
                    exc.code in (1000, 1001)
                    or exc.reason == "normal closure"
                    or "normal closure" in str(exc)
                ):
                    logger.debug(
                        "task_shutdown_completed_normally",
                        task_name=t.get_name(),
                        note="Task cancelled as requested",
                        close_code=exc.code,
                        close_reason=exc.reason,
                    )
                    return  # NOT fatal - this is expected during normal shutdown
                else:
                    # Log abnormal closures at warning level instead of error
                    logger.warning(
                        "background_task_closed_abnormally",
                        task_name=t.get_name(),
                        close_code=exc.code,
                        close_reason=exc.reason,
                    )
                    if self._last_spawner_error is None:
                        self._last_spawner_error = exc
                    return

            # ── all other exceptions are considered real failures ──────────────
            logger.error(
                "background_task_failed",
                task_name=t.get_name(),
                error=exc,
                exc_info=True,
            )
            if self._last_spawner_error is None:
                self._last_spawner_error = exc

        task.add_done_callback(_on_done)
        return task

    async def shutdown_tasks(
        self,
        *,
        grace_period: float = 2.0,
        cancel_hang: bool = True,
        join_timeout: float = 1.0,
    ):
        """
        Gracefully wait for *all* spawned tasks to finish.

        :param grace_period: how long to wait **before** issuing cancellation
        :param cancel_hang:  whether to cancel tasks that out-live *grace_period*
        :param join_timeout: per-task timeout when awaiting cancelled tasks
        """
        if not self._tasks:
            return

        # ── 1) Give tasks a chance to finish cleanly ────────────────────
        done, pending = await asyncio.wait(self._tasks, timeout=grace_period)

        # ── 2) Cancel stragglers (optional) ─────────────────────────────
        if pending and cancel_hang:
            for t in pending:
                t.cancel()
            for t in pending:
                try:
                    await asyncio.wait_for(t, timeout=join_timeout)
                except asyncio.TimeoutError:
                    logger.warning("task %s did not shut down in %.1fs", t.get_name(), join_timeout)
                except asyncio.CancelledError:
                    # This is expected when we cancel tasks - completely normal during shutdown
                    logger.debug(
                        "task_shutdown_completed_normally",
                        task_name=t.get_name(),
                        note="Task cancelled as requested",
                    )
                except Exception as exc:
                    logger.error(
                        "task %s raised during cancellation: %s",
                        t.get_name(),
                        exc,
                        exc_info=True,
                    )
                    if self._last_spawner_error is None:
                        self._last_spawner_error = exc

    # ── helper for callers that want to bubble the error themselves ─────
    @property
    def last_spawner_error(self) -> Optional[BaseException]:
        return self._last_spawner_error
