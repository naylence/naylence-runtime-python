from __future__ import annotations

import asyncio
import contextlib
import random
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Coroutine, List, Optional

from naylence.fame.core import (
    NodeWelcomeFrame,
    generate_id,
)
from naylence.fame.errors.errors import FameConnectError
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.session_manager import SessionManager
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.util.logging import getLogger
from naylence.fame.util.task_spawner import TaskSpawner

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike

__all__ = ["RootSessionManager"]

logger = getLogger(__name__)


class RootSessionManager(TaskSpawner, SessionManager):
    """
    Manages admission for root sentinels by handling hello/welcome exchanges
    with the admission service. Unlike UpstreamSessionManager, this does not
    manage connections or node attachments - it's purely for admission and
    obtaining grants like certificate signing.

    Key differences from UpstreamSessionManager:
    - No connection management (no FameConnector instances)
    - No node attachment handshake (NodeAttach → NodeAttachAck)
    - No heartbeat mechanism
    - No message queuing or routing
    - Focused on admission grants (e.g., certificate signing) only
    - Designed for root sentinels that don't need upstream connections
    - Simpler retry logic with configurable max attempts

    This is the first step toward generalizing session management to support
    different types of nodes with varying connectivity requirements.
    """

    # ---------- Tunables (override in subclass or via monkey-patch) ----------
    BACKOFF_INITIAL = 1.0  # seconds
    BACKOFF_CAP = 30.0  # seconds
    RETRY_MAX_ATTEMPTS = 5  # maximum retry attempts before giving up
    JWT_REFRESH_SAFETY = 60.0  # seconds before expiry to re-admit
    # ------------------------------------------------------------------------

    def __init__(
        self,
        *,
        node: NodeLike,
        admission_client: AdmissionClient,
        requested_logicals: list[str],
        on_welcome: Callable[
            [NodeWelcomeFrame], Coroutine[Any, Any, Any]
        ],  # callback to handle welcome grants
        on_epoch_change: Optional[
            Callable[[str], Coroutine[Any, Any, Any]]
        ] = None,  # callback for epoch change events (important for key exchange)
        on_admission_failed: Optional[
            Callable[[BaseException], Coroutine[Any, Any, Any]]
        ] = None,  # callback for admission failures
        enable_continuous_refresh: bool = True,  # whether to auto-refresh before expiry
    ) -> None:
        super().__init__()
        self._node = node
        self._admission_client = admission_client
        self._requested_logicals = requested_logicals
        self._on_welcome = on_welcome
        self._on_epoch_change = on_epoch_change
        self._on_admission_failed = on_admission_failed
        self._enable_continuous_refresh = enable_continuous_refresh

        # ───── runtime state ────────────────────────────────────────────────
        self._ready_evt = asyncio.Event()
        self._stop_evt = asyncio.Event()
        self._admission_task: Optional[asyncio.Task] = None
        self._expiry_guard_task: Optional[asyncio.Task] = None
        self._had_successful_admission = False
        self._admission_epoch = 0
        self._current_welcome_frame: Optional[NodeWelcomeFrame] = None

        logger.debug("created_root_session_manager")

    # --------------------------------------------------------------------------- #
    # PUBLIC API
    # --------------------------------------------------------------------------- #
    async def start(self, *, wait_until_ready: bool = True) -> None:
        """Start the manager.

        If *wait_until_ready* is True (default) this coroutine blocks until
        - the first admission succeeds  **or**
        - the background admission task terminates with an exception.

        That gives one-shot clients fail-fast behaviour while long-lived
        daemons can pass ``wait_until_ready=False`` to return immediately.
        """
        if self._admission_task:  # idempotent
            return

        logger.debug("root_session_manager_starting")
        self._stop_evt.clear()
        self._ready_evt.clear()

        # launch the admission task
        admission_task = self._admission_task = self.spawn(
            self._admission_loop(), name=f"root-admission-{self._admission_epoch}"
        )

        if not wait_until_ready:
            return

        ready_task = self.spawn(self._ready_evt.wait(), name=f"wait-ready-{self._admission_epoch}")
        done, _ = await asyncio.wait(
            {ready_task, self._admission_task}, return_when=asyncio.FIRST_COMPLETED
        )
        if admission_task in done:  # Admission task died first  →  bubble error
            exc = admission_task.exception()
            if exc:
                raise exc

        ready_task.cancel()

        logger.debug("root_session_manager_started")

    async def _sleep_with_stop(self, delay: float) -> None:
        """Sleep *delay* seconds but wake early if stop() is called."""
        try:
            await asyncio.wait_for(self._stop_evt.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    async def stop(self) -> None:
        logger.debug("root_session_manager_stopping")
        self._stop_evt.set()

        # Cancel and wait for admission task
        if self._admission_task:
            self._admission_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, BaseException):
                await self._admission_task
            self._admission_task = None

        # Cancel and wait for expiry guard task
        if self._expiry_guard_task:
            self._expiry_guard_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, BaseException):
                await self._expiry_guard_task
            self._expiry_guard_task = None

        logger.debug("root_session_manager_stopped")

    @property
    def is_ready(self) -> bool:
        """Return True once the first admission handshake has completed."""
        return self._ready_evt.is_set()

    @property
    def current_welcome_frame(self) -> Optional[NodeWelcomeFrame]:
        """Return the current welcome frame from the last successful admission."""
        return self._current_welcome_frame

    @property
    def admission_expires_at(self) -> Optional[datetime]:
        """Return the expiry time of the current admission."""
        return self._current_welcome_frame.expires_at if self._current_welcome_frame else None

    async def await_ready(self, timeout: float | None = None) -> None:
        if self.is_ready:
            return

        waiter = self.spawn(self._ready_evt.wait(), name=f"ready-waiter-{self._admission_epoch}")
        admission_task = self._admission_task
        if admission_task is None:
            waiter.cancel()
            return

        done, _ = await asyncio.wait(
            [waiter, admission_task],
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if admission_task in done:
            exc = admission_task.exception()
            if exc:
                raise exc
        waiter.cancel()

    async def perform_admission(self) -> NodeWelcomeFrame:
        """
        Perform a single admission exchange and return the welcome frame.
        This is useful for one-shot admission requests.

        As part of this process, ensures root identity initialization
        (similar to how UpstreamSessionManager handles identity on attach).
        """
        self._admission_epoch += 1

        # Initialize root identity before admission (symmetry with upstream attach)
        self._initialize_root_identity_if_needed()

        # 1. Admission ("hello → welcome")
        welcome = await self._admission_client.hello(
            system_id=self._node.id,  # root sentinel should have ID after initialization
            instance_id=generate_id(),
            requested_logicals=self._requested_logicals,
        )

        # Store the welcome frame for expiry tracking
        self._current_welcome_frame = welcome.frame

        # 2. Handle crypto preparation if path is assigned
        crypto_provider = get_crypto_provider()
        if welcome.frame.assigned_path and crypto_provider:
            crypto_provider.prepare_for_attach(
                welcome.frame.system_id,
                welcome.frame.assigned_path,
                welcome.frame.accepted_logicals or [],
            )

        return welcome.frame

    def _initialize_root_identity_if_needed(self) -> None:
        """
        Initialize root identity if needed.

        For root nodes, identity initialization happens automatically through
        the admission process and on_welcome callback. This method just ensures
        we have the minimum ID needed for the admission hello() call.
        """
        # Root identity initialization is handled through the normal admission flow:
        # 1. Ensure we have an ID for the hello() call (NoopAdmissionClient needs instance_id)
        # 2. perform_admission() calls admission_client.hello()
        # 3. NoopAdmissionClient returns a synthetic NodeWelcomeFrame with accepted_logicals
        # 4. The welcome frame is processed by self._on_welcome callback
        # 5. Node._on_welcome() sets all the node attributes (_id, _accepted_logicals, _physical_path, etc.)
        #
        # This approach is cleaner than manually setting attributes and avoids race conditions.

        node = self._node  # type: ignore

        # Only ensure we have an ID for the admission call - everything else is handled by on_welcome
        if not node.id:
            node._id = generate_id(mode="fingerprint")  # type: ignore[attr-defined]
            logger.debug("root_identity_generated_id_for_admission", system_id=node.id)

    async def handle_epoch_change(self, epoch: str) -> None:
        """
        Handle epoch change events.

        This method is important for triggering key exchanges and other
        epoch-sensitive operations in the security manager.

        Args:
            epoch: The new epoch identifier
        """
        if self._on_epoch_change:
            await self._on_epoch_change(epoch)
        else:
            logger.debug("epoch_change_ignored_no_handler", epoch=epoch)

    async def _admission_loop(self) -> None:
        """Admission loop: perform admission → handle grants → monitor expiry → retry on error."""
        delay = self.BACKOFF_INITIAL
        attempts = 0

        while not self._stop_evt.is_set() and attempts < self.RETRY_MAX_ATTEMPTS:
            try:
                attempts += 1
                welcome_frame = await self.perform_admission()

                # Handle the welcome frame and its grants
                await self._on_welcome(welcome_frame)

                # ─── first successful admission? signal readiness ──────────────────
                if not self._ready_evt.is_set():
                    self._ready_evt.set()

                if self._had_successful_admission:
                    logger.debug("root_admission_refreshed")
                else:
                    logger.debug("root_admission_completed")

                self._had_successful_admission = True
                delay = self.BACKOFF_INITIAL  # reset after each success
                attempts = 0  # reset attempts counter

                # Start expiry guard if continuous refresh is enabled and there's an expiry
                if self._enable_continuous_refresh and welcome_frame.expires_at:
                    await self._start_expiry_guard(welcome_frame)
                    # Wait for either expiry trigger or stop event
                    expiry_triggered = await self._wait_for_expiry_or_stop()
                    if expiry_triggered and not self._stop_evt.is_set():
                        # Continue the loop to perform re-admission
                        logger.debug("performing_scheduled_re_admission")
                        continue
                    else:
                        # Stop was requested
                        return
                else:
                    # For one-shot admission without continuous refresh, we're done
                    return

            except asyncio.CancelledError:
                raise
            except FameConnectError as e:
                logger.warning(
                    "root_admission_failed",
                    error=e,
                    attempt=attempts,
                    will_retry=attempts < self.RETRY_MAX_ATTEMPTS,
                )
                if not self._had_successful_admission and attempts >= self.RETRY_MAX_ATTEMPTS:
                    if self._on_admission_failed:
                        await self._on_admission_failed(e)
                    raise  # fail-fast on repeated first attempt failures
                if attempts < self.RETRY_MAX_ATTEMPTS:
                    delay = await self._apply_backoff(delay)
            except Exception as e:
                logger.warning(
                    "root_admission_failed",
                    error=e,
                    attempt=attempts,
                    will_retry=attempts < self.RETRY_MAX_ATTEMPTS,
                    exc_info=True,
                )
                if not self._had_successful_admission and attempts >= self.RETRY_MAX_ATTEMPTS:
                    if self._on_admission_failed:
                        await self._on_admission_failed(e)
                    raise  # fail-fast on repeated first attempt failures
                if attempts < self.RETRY_MAX_ATTEMPTS:
                    delay = await self._apply_backoff(delay)

        if attempts >= self.RETRY_MAX_ATTEMPTS:
            logger.error("root_admission_max_attempts_exceeded", max_attempts=self.RETRY_MAX_ATTEMPTS)

    async def _apply_backoff(self, delay: float) -> float:
        """Sleep with stop-interrupt and return the next delay."""
        await self._sleep_with_stop(delay + random.uniform(0, delay))
        return min(delay * 2, self.BACKOFF_CAP)

    async def _start_expiry_guard(self, welcome_frame: NodeWelcomeFrame) -> None:
        """Start the expiry guard task to monitor admission expiry."""
        # Cancel any existing expiry guard
        if self._expiry_guard_task and not self._expiry_guard_task.done():
            self._expiry_guard_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._expiry_guard_task

        # Start new expiry guard
        self._expiry_guard_task = self.spawn(
            self._expiry_guard(welcome_frame),
            name=f"root-expiry-guard-{self._admission_epoch}",
        )

    async def _wait_for_expiry_or_stop(self) -> bool:
        """
        Wait for either expiry guard to complete or stop event.
        Returns True if expiry was triggered, False if stop was requested.
        """
        if not self._expiry_guard_task:
            return False

        stop_task = self.spawn(self._stop_evt.wait(), name="wait-stop")
        done, pending = await asyncio.wait(
            [self._expiry_guard_task, stop_task], return_when=asyncio.FIRST_COMPLETED
        )

        # Cancel pending tasks
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        # Return True if expiry guard completed (not cancelled)
        if self._expiry_guard_task in done:
            return not self._expiry_guard_task.cancelled()
        else:
            return False

    async def _expiry_guard(self, welcome_frame: NodeWelcomeFrame) -> None:
        """
        Monitor admission expiry and complete when it's time to refresh.
        """
        if not welcome_frame.expires_at:
            logger.debug("no_admission_expiry_configured")
            # Wait indefinitely if no expiry is set
            await self._stop_evt.wait()
            return

        now = datetime.now(timezone.utc)
        delay = (welcome_frame.expires_at - now).total_seconds() - self.JWT_REFRESH_SAFETY
        delay = max(delay, 0)  # Don't allow negative delays

        logger.debug(
            "admission_expiry_guard_started",
            welcome_expires_at=welcome_frame.expires_at.isoformat(),
            delay_seconds=delay,
            refresh_safety_seconds=self.JWT_REFRESH_SAFETY,
        )

        if delay > 0:
            try:
                await asyncio.wait_for(self._stop_evt.wait(), timeout=delay)
                # Stop event was set before expiry
                return
            except asyncio.TimeoutError:
                # Timeout occurred - time to refresh
                pass

        logger.debug(
            "admission_expiry_triggered_refresh",
            expires_at=welcome_frame.expires_at.isoformat(),
            current_time=datetime.now(timezone.utc).isoformat(),
            seconds_before_expiry=self.JWT_REFRESH_SAFETY,
        )

    @staticmethod
    def create_for_root_sentinel(
        node,
        admission_client,
        requested_logicals: Optional[List[str]] = None,
        enable_continuous_refresh: bool = True,
        on_epoch_change: Optional[Callable[[str], Coroutine[Any, Any, Any]]] = None,
    ):
        """
        Factory method to create a RootSessionManager configured for typical
        root sentinel usage patterns.

        Args:
            node: The root sentinel node
            admission_client: Client for admission service communication
            requested_logicals: List of logical addresses to request
            enable_continuous_refresh: Whether to auto-refresh before expiry
            on_epoch_change: Optional callback for epoch change events
                           (important for triggering key exchanges)

        Returns:
            A configured RootSessionManager instance
        """

        async def handle_welcome(frame: NodeWelcomeFrame) -> None:
            """Default welcome handler that processes grants."""
            logger.info(
                "root_admission_successful",
                system_id=frame.system_id,
                assigned_path=frame.assigned_path,
                accepted_logicals=frame.accepted_logicals,
                grants_count=len(frame.connection_grants or []),
            )

            # Process any certificate signing grants or other grants
            grants = frame.connection_grants or []
            for grant in grants:
                grant_purpose = grant.get("purpose")
                if grant_purpose:
                    logger.debug("received_admission_grant", purpose=grant_purpose)

        async def handle_failure(exc: BaseException) -> None:
            """Default failure handler."""
            logger.error("root_admission_failed_permanently", error=str(exc))

        return RootSessionManager(
            node=node,
            admission_client=admission_client,
            requested_logicals=requested_logicals or [],
            on_welcome=handle_welcome,
            on_admission_failed=handle_failure,
            enable_continuous_refresh=enable_continuous_refresh,
            on_epoch_change=on_epoch_change,
        )
