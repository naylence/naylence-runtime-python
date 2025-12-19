from __future__ import annotations

import asyncio
import contextlib
import random
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Optional, cast

from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.core import (
    DeliveryAckFrame,
    DeliveryOriginType,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    FameEnvelopeWith,
    FameFabric,
    NodeAttachAckFrame,
    NodeHeartbeatAckFrame,
    NodeHeartbeatFrame,
    NodeWelcomeFrame,
    SecurityContext,
    generate_id,
)
from naylence.fame.errors.errors import (
    FameConnectError,
    FameMessageTooLarge,
    FameTransportClose,
)
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.node_attach_client import AttachInfo, NodeAttachClient
from naylence.fame.node.connection_retry_policy import (
    ConnectionRetryContext,
    ConnectionRetryPolicy,
)
from naylence.fame.node.session_manager import SessionManager
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.util.logging import getLogger
from naylence.fame.util.task_spawner import TaskSpawner

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike

__all__ = ["UpstreamSessionManager"]

logger = getLogger(__name__)


class UpstreamSessionManager(TaskSpawner, SessionManager):
    """
    Keeps a child FameNode attached to its parent, independent of the underlying
    transport.  Handles admission, (re-)attachment, heart-beats, token refresh
    and bounded offline buffering.
    """

    # ---------- Tunables (override in subclass or via monkey-patch) ----------
    HEARTBEAT_INTERVAL = 15.0  # seconds  (LB idle timeouts are ~60 s)
    HEARTBEAT_GRACE = 2.0  # allowed missed-beat factor
    JWT_REFRESH_SAFETY = 60.0  # seconds before expiry to reconnect
    TX_QUEUE_MAX = 512

    BACKOFF_INITIAL = 1.0  # seconds
    BACKOFF_CAP = 30.0  # seconds
    # ------------------------------------------------------------------------

    def __init__(
        self,
        *,
        node: NodeLike,
        attach_client: NodeAttachClient,
        requested_logicals: list[str],
        outbound_origin_type: DeliveryOriginType,
        inbound_origin_type: DeliveryOriginType,
        inbound_handler: FameEnvelopeHandler,  # node's own handler
        on_welcome: Callable[[NodeWelcomeFrame], Coroutine[Any, Any, Any]],  # callback to persist ids/paths
        on_attach: Callable[[AttachInfo, FameConnector], Coroutine[Any, Any, Any]],
        on_epoch_change: Callable[[str], Coroutine[Any, Any, Any]],
        admission_client: Optional[AdmissionClient] = None,
        retry_policy: Optional[ConnectionRetryPolicy] = None,
    ) -> None:
        super().__init__()
        self._node = node

        self._outbound_origin_type = outbound_origin_type
        self._inbound_origin_type = inbound_origin_type
        self._admission_client = admission_client or node.admission_client
        self._attach_client = attach_client
        # self._connector_factory = connector_factory
        self._requested_logicals = requested_logicals
        self._on_welcome = on_welcome
        self._on_attach = on_attach
        self._on_epoch_change = on_epoch_change

        # Store the connection retry policy (can be None, in which case default behavior applies)
        self._connection_retry_policy = retry_policy
        self._initial_attempts = 0

        # ───── runtime state ────────────────────────────────────────────────
        self._message_queue: asyncio.Queue[FameEnvelope] = asyncio.Queue(self.TX_QUEUE_MAX)
        self._ready_evt = asyncio.Event()
        self._stop_evt = asyncio.Event()
        self._fsm_task: Optional[asyncio.Task] = None
        self._connector: Optional[FameConnector] = None
        self._target_system_id: Optional[str] = None
        self._physical_path: Optional[str] = None
        self._last_hb_ack_time: Optional[float] = None
        self._wrapped_handler = self._make_heartbeat_enabled_handler(inbound_handler)
        self._last_seen_epoch = None
        self._had_successful_attach = False
        self._connect_epoch = 0

        logger.debug(
            "created_upstream_session_manager",
            target_system_id=self._target_system_id,
            has_retry_policy=self._connection_retry_policy is not None,
        )

    # --------------------------------------------------------------------------- #
    # PUBLIC API
    # --------------------------------------------------------------------------- #
    async def start(self, *, wait_until_ready: bool = True) -> None:
        """Start the manager.

        If *wait_until_ready* is True (default) this coroutine blocks until
        - the first attach succeeds  **or**
        - the background FSM task terminates with an exception.

        That gives one-shot clients fail-fast behaviour while long-lived
        daemons can pass ``wait_until_ready=False`` to return immediately.
        """
        if self._fsm_task:  # idempotent
            return

        logger.debug("upstream_session_manager_starting")
        self._stop_evt.clear()
        self._ready_evt.clear()

        # launch the reconnect FSM
        fsm_task = self._fsm_task = self.spawn(self._fsm_loop(), name=f"upstream-fsm-{self._connect_epoch}")

        if not wait_until_ready:
            return

        ready_task = self.spawn(self._ready_evt.wait(), name=f"wait-ready-{self._connect_epoch}")
        done, _ = await asyncio.wait({ready_task, self._fsm_task}, return_when=asyncio.FIRST_COMPLETED)
        if fsm_task in done:  # FSM died first  →  bubble error
            exc = fsm_task.exception()
            if exc:
                raise exc

        ready_task.cancel()

        logger.debug("upstream_session_manager_started")

    async def _sleep_with_stop(self, delay: float) -> None:
        """Sleep *delay* seconds but wake early if stop() is called."""
        try:
            await asyncio.wait_for(self._stop_evt.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    async def stop(self) -> None:
        logger.debug("upstream_session_manager_stopping")
        self._stop_evt.set()

        if self._fsm_task:
            self._fsm_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._fsm_task
            self._fsm_task = None

        if self._connector:
            await self._connector.stop()
            self._connector = None

        logger.debug("upstream_session_manager_stopped")

    @property
    def system_id(self) -> Optional[str]:
        return self._target_system_id

    async def send(self, env: FameEnvelope) -> None:
        await self._message_queue.put(env)  # may raise QueueFull – caller decides policy

    async def _fsm_loop(self) -> None:
        """Reconnect loop: attach → run helper tasks → re-attach on error."""
        delay = self.BACKOFF_INITIAL
        self._initial_attempts = 0

        while not self._stop_evt.is_set():
            self._initial_attempts += 1

            try:
                await self._connect_cycle()
                delay = self.BACKOFF_INITIAL  # reset after each success
                self._initial_attempts = 0  # reset on success
            except asyncio.CancelledError:
                raise
            except (FameTransportClose, FameConnectError) as e:
                should_fail_fast = self._should_fail_fast_on_error(e)
                logger.warning(
                    "upstream_link_closed",
                    error=e,
                    will_retry=not should_fail_fast,
                    attempt=self._initial_attempts,
                    has_retry_policy=self._connection_retry_policy is not None,
                )
                if should_fail_fast and isinstance(e, FameConnectError):
                    raise  # fail-fast when configured
                delay = await self._apply_backoff(delay)
            except Exception as e:
                should_fail_fast = self._should_fail_fast_on_error(e)
                logger.warning(
                    "upstream_link_closed",
                    error=e,
                    will_retry=not should_fail_fast,
                    attempt=self._initial_attempts,
                    has_retry_policy=self._connection_retry_policy is not None,
                    exc_info=True,
                )
                if should_fail_fast:
                    raise  # fail-fast when configured
                delay = await self._apply_backoff(delay)

    def _should_fail_fast_on_error(self, error: BaseException) -> bool:
        """
        Determine whether to fail immediately or continue retrying.
        Returns True if we should raise the error instead of retrying.
        """
        # If no policy is configured, use legacy behavior (fail-fast after first attempt)
        if self._connection_retry_policy is None:
            # After first successful attach, always retry (existing behavior)
            if self._had_successful_attach:
                return False
            # Without a policy, fail on first error
            return True

        # Delegate decision to the policy
        context = ConnectionRetryContext(
            had_successful_attach=self._had_successful_attach,
            attempt_number=self._initial_attempts,
            error=error,
        )
        should_retry = self._connection_retry_policy.should_retry(context)

        return not should_retry

    async def _apply_backoff(self, delay: float) -> float:
        """Sleep with stop-interrupt and return the next delay."""
        await self._sleep_with_stop(delay + random.uniform(0, delay))
        return min(delay * 2, self.BACKOFF_CAP)

    def _get_node_attach_grant(self, connection_grants: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Get the node attach grant from the list of connection grants."""
        for grant in connection_grants:
            if grant.get("purpose") == GRANT_PURPOSE_NODE_ATTACH:
                return grant
        return None

    async def _connect_cycle(self) -> None:
        assert self._admission_client, "Node must have an admission client"

        self._connect_epoch += 1

        # 1. Admission ("hello → welcome")
        welcome = await self._admission_client.hello(
            system_id=self._node.id,  # child may not know yet
            instance_id=generate_id(),
            requested_logicals=self._requested_logicals,
        )

        # Get connection grants from welcome frame
        connection_grants = welcome.frame.connection_grants
        if not connection_grants:
            raise RuntimeError("welcome frame missing connection grants")

        grant = self._get_node_attach_grant(connection_grants)

        if not grant:
            raise RuntimeError("welcome frame missing node attach grant")

        crypto_provider = get_crypto_provider()

        if welcome.frame.assigned_path:
            crypto_provider.prepare_for_attach(
                welcome.frame.system_id,
                welcome.frame.assigned_path,
                welcome.frame.accepted_logicals or [],
            )

        await self._on_welcome(welcome.frame)

        # 2. Create connector from grant

        connector: FameConnector = await ConnectorFactory.create_connector(
            grant, system_id=welcome.frame.system_id
        )

        # Start the connector
        await connector.start(self._wrapped_handler)
        self._connector = connector

        # 3. Attach
        # Get supported inbound connectors directly from the node
        callback_grants = self._node.gather_supported_callback_grants()

        attach_info = await self._attach_client.attach(
            self._node,
            origin_type=self._outbound_origin_type,
            connector=connector,
            welcome_frame=welcome.frame,
            final_handler=self._wrapped_handler,
            keys=self._get_keys(),
            callback_grants=callback_grants,
        )

        self._target_system_id = attach_info.get("target_system_id")
        self._physical_path = attach_info.get("assigned_path")

        await self._on_attach(attach_info, connector)

        epoch = attach_info.get("routing_epoch")
        if epoch and epoch != self._last_seen_epoch:
            self._last_seen_epoch = epoch
            if self._on_epoch_change:
                self.spawn(
                    self._on_epoch_change(epoch),
                    name=f"epoch-change-{epoch}",
                )
            else:
                logger.warning("parent_epoch_changed", epoch=epoch)

        # ─── first successful attach? signal readiness ──────────────────
        if not self._ready_evt.is_set():
            self._ready_evt.set()

        if not self._message_queue.empty():
            logger.debug("flushing_buffered_frames", queue_size=self._message_queue.qsize())

        # 4. Ancillary tasks that live with the connection
        stop_subtasks = asyncio.Event()
        heartbeat_task = self.spawn(
            self._heartbeat_loop(connector, stop_subtasks),
            name=f"upstream-heartbeat-{self._connect_epoch}",
        )
        message_pump_task = self.spawn(
            self._message_pump_loop(connector, stop_subtasks),
            name=f"message-pump-{self._connect_epoch}",
        )
        attach_expires_at = attach_info.get("attach_expires_at")

        expiry_guard_task = self.spawn(
            self._expiry_guard(connector, welcome, attach_info, stop_subtasks),
            name=f"expiry-guard-{self._connect_epoch}",
        )

        attach_expires_at_str = (
            attach_expires_at.isoformat(timespec="seconds") if attach_expires_at else None
        )

        if self._had_successful_attach:
            logger.debug("reconnected_to_upstream", attach_expires_at=attach_expires_at_str)
        else:
            logger.debug("connected_to_upstream", attach_expires_at=attach_expires_at_str)

        self._had_successful_attach = True

        tasks = [heartbeat_task, message_pump_task, expiry_guard_task]
        failure: Exception | None = None

        try:
            # Wait until one helper fails or stop() is requested.
            await self._wait_for_failure_or_stop(tasks)
        except Exception as exc:  # ← remember the reason
            failure = exc
        finally:
            # Always tear everything down.
            stop_subtasks.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            with contextlib.suppress(Exception):
                await connector.stop()
            self._connector = None

        # Bubble the original failure so the FSM starts a new cycle.
        if failure is not None:
            raise failure

    def _get_keys(self) -> Optional[list[dict]]:
        # TODO: move to a centralized location

        if (
            not self._node
            or not self._node.security_manager
            or not self._node.security_manager.supports_overlay_security
        ):
            return None

        crypto_provider = get_crypto_provider()
        if not crypto_provider:
            return None

        keys = []

        # Try to get certificate-enabled signing JWK
        node_jwk = crypto_provider.node_jwk()
        if node_jwk:
            keys.append(node_jwk)

        # Always get all keys from JWKS (includes encryption keys and fallback signing key)
        jwks = crypto_provider.get_jwks()
        if jwks and jwks.get("keys"):
            for jwk in jwks["keys"]:
                # If we already have a certificate-enabled signing key, skip the regular signing key
                if node_jwk and jwk.get("kid") == node_jwk.get("kid") and jwk.get("use") != "enc":
                    continue
                keys.append(jwk)

        return keys if keys else None

    def is_ready(self) -> bool:
        """Return True once the first attach handshake has completed."""
        return self._ready_evt.is_set()

    async def await_ready(self, timeout: float | None = None) -> None:
        if self.is_ready():
            return

        waiter = self.spawn(self._ready_evt.wait(), name=f"ready-waiter-{self._connect_epoch}")
        fsm_task = cast(asyncio.Task[Any], self._fsm_task)  # self._fsm_task is not None here
        done, _ = await asyncio.wait(
            [waiter, fsm_task],
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if fsm_task in done:
            exc = fsm_task.exception()
            if exc:
                raise exc
        waiter.cancel()

    async def _wait_for_failure_or_stop(self, tasks: list[asyncio.Task[Any]]) -> None:
        """Return when *any* helper task errors **or** stop() is requested."""
        stop_wait = self.spawn(self._stop_evt.wait(), name="stop-wait")
        done, _ = await asyncio.wait(tasks + [stop_wait], return_when=asyncio.FIRST_COMPLETED)

        if self._stop_evt.is_set():  # graceful shutdown path
            for t in tasks:
                t.cancel()
            stop_wait.cancel()
            return

        # Always cancel the stop_wait task before propagating errors
        stop_wait.cancel()

        # propagate the first helper error to upper layers
        for t in done:
            exc = t.exception()
            if exc:
                raise exc

    async def _heartbeat_loop(self, c: FameConnector, stop_evt: asyncio.Event) -> None:
        logger.debug("starting_heartbeat_loop")
        interval = self.HEARTBEAT_INTERVAL
        grace = interval * self.HEARTBEAT_GRACE
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()

        self._last_hb_ack_time = loop.time()

        while not stop_evt.is_set():
            # sleep, but wake up immediately if the supervisor asks us to stop
            try:
                # wait either for stop_evt or for the interval to elapse
                await asyncio.wait_for(stop_evt.wait(), timeout=interval)
                continue  # stop_evt set  →  while-condition will exit
            except asyncio.TimeoutError:
                pass  # interval elapsed – send heartbeat

            hb_env = await self._make_heartbeat_envelope()
            logger.debug(
                "sending_heartbeat",
                hb_corr_id=hb_env.corr_id,
                hb_env_id=hb_env.id,
            )
            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL,
            )
            try:
                await self._node._dispatch_envelope_event(
                    "on_forward_upstream", self._node, hb_env, context=context
                )
                await c.send(hb_env)
            except Exception as e:
                await self._node._dispatch_envelope_event(
                    "on_forward_upstream_complete", self._node, hb_env, error=e, context=context
                )
                raise
            else:
                await self._node._dispatch_envelope_event(
                    "on_forward_upstream_complete", self._node, hb_env, context=context
                )

            await self._node._dispatch_event("on_heartbeat_sent", hb_env)

            # Check for missed heartbeat acknowledgements
            if self._last_hb_ack_time is not None and loop.time() - self._last_hb_ack_time > grace:
                raise FameConnectError(
                    f"missed heartbeat acknowledgement for hb_env_id: {hb_env.id}, "
                    f"hb_corr_id: {hb_env.corr_id}"
                )

            # ack timestamp is updated by the wrapped inbound handler

        logger.debug("completed_heartbeat_loop")

    async def _message_pump_loop(
        self,
        connector: FameConnector,
        stop_evt: asyncio.Event,
    ) -> None:
        while not stop_evt.is_set():
            try:
                # Use asyncio.wait_for to avoid hanging on queue.get()
                get_task = asyncio.create_task(self._message_queue.get())
                stop_task = asyncio.create_task(stop_evt.wait())

                done, pending = await asyncio.wait(
                    [get_task, stop_task], return_when=asyncio.FIRST_COMPLETED
                )

                # Cancel any pending tasks
                for task in pending:
                    task.cancel()

                if stop_evt.is_set():
                    # If we got a message but stop was set, put it back
                    if get_task.done() and not get_task.exception():
                        env = get_task.result()
                        await self._message_queue.put(env)
                    return

                # We got a message, process it
                env = get_task.result()

            except asyncio.CancelledError:
                return

            try:
                await connector.send(env)
            except FameMessageTooLarge as e:
                logger.error(f"Failed to send message: {e}", exc_info=True)
                await self._handle_message_too_large(env, str(e))
            except FameTransportClose:
                # Connector told us the link is gone – push the frame back and
                # bubble so the FSM restarts the whole attach cycle.
                await self._message_queue.put(env)
                raise

    async def _handle_message_too_large(self, env: FameEnvelope, reason: str):
        corr_id = env.corr_id
        nack_destination = env.reply_to
        if nack_destination and corr_id:
            fabric = FameFabric.current()
            nack = self._node.envelope_factory.create_envelope(
                to=nack_destination,
                frame=DeliveryAckFrame(
                    ok=False,
                    ref_id=env.id,
                    code="MESSAGE_TOO_LARGE",
                    reason=reason,
                ),
                corr_id=corr_id,
            )
            await fabric.send(nack)

    async def _expiry_guard(
        self,
        c: FameConnector,
        welcome: FameEnvelopeWith[NodeWelcomeFrame],
        info: AttachInfo,
        stop_evt: asyncio.Event,
    ) -> None:
        ts = [
            welcome.frame.expires_at,
            info.get("attach_expires_at"),
        ]
        ts = [t for t in ts if t is not None]
        if not ts:
            logger.debug("no_ttl_expiry_configured")
            await stop_evt.wait()
            return

        earliest = min(ts)
        now = datetime.now(timezone.utc)
        delay = (earliest - now).total_seconds() - self.JWT_REFRESH_SAFETY
        delay = max(delay, self.JWT_REFRESH_SAFETY)  # cap at JWT_REFRESH_SAFETY

        logger.debug(
            "ttl_expiry_guard_started",
            welcome_expires_at=(welcome.frame.expires_at.isoformat() if welcome.frame.expires_at else None),
            attach_expires_at=info.get("attach_expires_at"),
            earliest_expiry=earliest.isoformat(),
            delay_seconds=delay,
            refresh_safety_seconds=self.JWT_REFRESH_SAFETY,
        )

        if delay > 0:
            sleep_task = self.spawn(asyncio.sleep(delay), name=f"jwt-sleep-{self._connect_epoch}")
            stop_task = self.spawn(stop_evt.wait(), name=f"jwt-stop-{self._connect_epoch}")
            done, _ = await asyncio.wait([sleep_task, stop_task], return_when=asyncio.FIRST_COMPLETED)
            for t in (sleep_task, stop_task):
                if not t.done():
                    t.cancel()

        if not stop_evt.is_set():
            logger.debug(
                "ttl_expiry_triggered_reconnect",
                expires_at=earliest.isoformat(),
                current_time=datetime.now(timezone.utc).isoformat(),
                seconds_before_expiry=self.JWT_REFRESH_SAFETY,
            )
            await c.stop()  # triggers new admission/attach

    async def _make_heartbeat_envelope(self) -> FameEnvelopeWith[NodeHeartbeatFrame]:
        env = self._node.envelope_factory.create_envelope(frame=NodeHeartbeatFrame(), corr_id=generate_id())
        return cast(
            FameEnvelopeWith[NodeHeartbeatFrame],
            env,
        )

    def _make_heartbeat_enabled_handler(self, downstream: FameEnvelopeHandler) -> FameEnvelopeHandler:
        """
        Intercepts NodeHeartbeatAck frames to refresh the watchdog timer,
        delegates everything else to the node's own handler.
        """

        # Don't initialize _last_hb_ack_time here - it will be set when heartbeat loop starts

        async def handler(env: FameEnvelope, context: Optional[FameDeliveryContext] = None):
            authorization_context = self._connector.authorization_context if self._connector else None
            if context is None:
                context = FameDeliveryContext(
                    origin_type=self._inbound_origin_type,
                    from_connector=self._connector,
                    from_system_id=self._target_system_id,
                    security=SecurityContext(authorization=authorization_context),
                )
            else:
                context.origin_type = self._inbound_origin_type
                context.from_connector = self._connector
                context.from_system_id = self._target_system_id
                if context.security is None:
                    context.security = SecurityContext()
                if context.security.authorization is None:
                    context.security.authorization = authorization_context

            await self._node._dispatch_envelope_event("on_envelope_received", self._node, env, context)

            # (1) normal heartbeat
            if isinstance(env.frame, NodeHeartbeatAckFrame):
                logger.debug(
                    "received_heartbeat_ack",
                    hb_ack_env_id=env.id,
                    hb_ack_corr_id=env.corr_id,
                    hb_routing_epoch=env.frame.routing_epoch,
                )

                # if env.sec and env.sec.sig:
                # Delegate heartbeat verification to event listeners
                await self._node._dispatch_event("on_heartbeat_received", env)

                self._last_hb_ack_time = asyncio.get_running_loop().time()
                epoch = env.frame.routing_epoch
                if epoch and epoch != self._last_seen_epoch:
                    self._last_seen_epoch = epoch
                    if self._on_epoch_change:
                        await self._on_epoch_change(epoch)
                    else:
                        logger.warning("parent_epoch_changed", epoch=epoch)
                return  # ← keep it in the control-plane

            # (2) duplicate control-plane ack after a reconnect
            #     (do **not** let this reach the router)
            if isinstance(env.frame, NodeAttachAckFrame):
                return

            # (3) everything else is app traffic
            return await downstream(env, context)

        return handler
