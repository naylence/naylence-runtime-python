import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from pydantic import ValidationError

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.connector.connector_factory import ConnectorFactory
from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameConnector,
    FameEnvelope,
    create_resource,
)
from naylence.fame.node.node_context import (
    FameAuthorizedDeliveryContext,
    FameNodeAuthorizationContext,
)
from naylence.fame.sentinel.store.route_store import RouteStore, get_default_route_store
from naylence.fame.util import logging
from naylence.fame.util.task_spawner import (
    TaskSpawner,
)  # Adjust the import path as needed

# Import or define ConnectorFactory

logger = logging.getLogger(__name__)


@dataclass
class AddressRouteInfo:
    """Rich routing information for an address binding."""

    segment: str
    physical_path: Optional[str] = None
    encryption_key_id: Optional[str] = None
    last_updated: Optional[datetime] = None

    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now(timezone.utc)


class RouteManager(TaskSpawner):
    def __init__(
        self,
        deliver: Callable[[FameEnvelope, FameAuthorizedDeliveryContext], Awaitable[None]],
        route_store: RouteStore,
        get_id: Optional[Callable[[], str]] = None,
    ) -> None:
        TaskSpawner.__init__(self)
        # self.connector_factory: Optional[ConnectorFactory] = connector_factory
        self._pools: dict[str, set[str]] = {}  # Pool of segments
        self._downstream_routes: dict[str, FameConnector] = {}
        self._downstream_route_store = route_store

        self._downstream_addresses_routes: dict[FameAddress, AddressRouteInfo] = {}

        self._flow_routes: dict[str, FameConnector] = {}
        self._get_id = get_id or (lambda: "")

        self._deliver = deliver

        self._peer_routes: dict[str, FameConnector] = {}
        self._peer_route_store: RouteStore = route_store or get_default_route_store()

        self._peer_addresses_routes: dict[FameAddress, str] = {}

        self._pending_routes: dict[str, tuple[FameConnector, asyncio.Event, list[FameEnvelope]]] = {}
        self._pending_route_metadata: dict[str, ConnectorConfig] = {}

        self._stop_event = asyncio.Event()
        self._routes_lock = asyncio.Lock()

    async def start(self) -> None:
        await self.restore_routes()

    async def stop(self) -> None:
        async with self._routes_lock:
            for connector in self._downstream_routes.values():
                await self._safe_stop(connector)
            self._downstream_routes.clear()
            self._downstream_addresses_routes.clear()
            self._peer_routes.clear()
            self._peer_addresses_routes.clear()

        self._pending_routes.clear()
        self._pending_route_metadata.clear()

    @property
    def downstream_routes(self) -> dict[str, FameConnector]:
        """Get the downstream routes."""
        return self._downstream_routes

    @property
    def routes_lock(self) -> asyncio.Lock:
        """Get the lock for managing routes."""
        return self._routes_lock

    @property
    def downstream_route_store(self) -> RouteStore:
        """Get the route store for downstream routes."""
        return self._downstream_route_store

    async def register_downstream_route(self, segment: str, route: FameConnector) -> None:
        async with self.routes_lock:
            self.downstream_routes[segment] = route
        logger.debug("registered_downstream_route", route=segment)

    async def unregister_dowstream_route(self, segment: str) -> None:
        async with self.routes_lock:
            self._downstream_routes.pop(segment, None)

    async def remove_route(
        self,
        segment: str,
        routes: dict[str, FameConnector],
        route_store: RouteStore,
        *,
        stop: bool = True,
    ) -> None:
        async with self._routes_lock:
            conn = routes.pop(segment, None)
        if conn and stop:
            try:
                await self._safe_stop(conn)
            except Exception:  # pragma: no cover – defensive
                logger.error("error_stopping_connector", segment)

        # purge address / pool maps
        routes = {a: s for a, s in routes.items() if s != segment}

        for pool in self._pools.values():
            pool.discard(segment)

        # drop persisted entry so we don’t resurrect a dead route on restart
        await route_store.delete(segment)
        logger.debug("removed_route", segment=segment)

    async def restore_routes(self) -> None:
        """Re-establish durable routes from *RouteStore* at startup."""
        # if not self.connector_factory:
        #     raise RuntimeError("Routing node is missing connector factory")
        entries = await self._downstream_route_store.list()
        now = datetime.now(timezone.utc)
        for segment, entry in entries.items():
            if entry.attach_expires_at and entry.attach_expires_at < now:
                logger.debug("skipping_expired_route", segment=segment)
                continue

            # 1) Validate stored auth context
            try:
                auth_context = FameNodeAuthorizationContext.model_validate(entry.metadata, by_alias=True)
            except ValidationError:
                logger.exception("[RoutingNode] Corrupt metadata for route '%s' - skipping", segment)
                continue

            if not entry.connector_config:
                logger.warning(f"Cannot restore route, entry missing connector config: {entry}")
                continue

            # 2) Re-create connector with exponential-back-off
            backoff = 2.0
            for attempt in range(1, 4):
                try:
                    # connector = await self.connector_factory.create(entry.connector_config)
                    connector = await create_resource(ConnectorFactory, entry.connector_config)
                    node_ctx = FameAuthorizedDeliveryContext(
                        from_connector=connector,
                        authorization=auth_context,
                        from_system_id=segment,
                        origin_type=DeliveryOriginType.DOWNSTREAM,
                    )
                    await connector.start(lambda env, _=None: self._deliver(env, node_ctx))

                    async with self._routes_lock:
                        self._downstream_routes[segment] = connector

                    if entry.attach_expires_at:
                        delay = (entry.attach_expires_at - now).total_seconds()
                        self.spawn(
                            self.expire_route_later(segment, delay),
                            name=f"expire-restore-{self._get_id()}",
                        )
                    break  # success
                except (asyncio.TimeoutError, ConnectionError, OSError):
                    logger.warning(
                        "[RoutingNode] Transient restore failure '%s' (attempt %d) - retrying",
                        segment,
                        attempt,
                    )
                    await asyncio.sleep(backoff)
                    backoff *= 2
                except Exception as e:
                    logger.error("failed_to_restore_route", segment=segment, error=str(e))
                    break

    async def expire_route_later(self, segment: str, delay: float) -> None:
        await asyncio.sleep(delay)
        async with self._routes_lock:
            connector = self._downstream_routes.pop(segment, None)
        if connector:
            await self._safe_stop(connector)
        await self._downstream_route_store.delete(segment)
        logger.debug("expired_route", route=segment)

    async def _remove_downstream_route(self, segment: str, *, stop: bool = True) -> None:
        await self.remove_route(
            segment,
            self._downstream_routes,
            self.downstream_route_store,
            stop=stop,
        )

    async def _safe_stop(self, connector: FameConnector) -> None:
        """Stop a connector, swallowing *CancelledError* for idempotent cleanup."""
        with contextlib.suppress(asyncio.CancelledError):
            await connector.stop()

        to_remove = [fid for fid, peer in self._flow_routes.items() if peer is connector]
        for fid in to_remove:
            self._flow_routes.pop(fid, None)

    # ---------------------------------------------------------------------------------- janitor
    async def _janitor_loop(self) -> None:
        """Background task that expires routes when their *attach_expires_at* elapses."""
        try:
            while not self._stop_event.is_set():
                for route_store in [
                    self._downstream_route_store,
                    self._peer_route_store,
                ]:
                    now = datetime.now(timezone.utc)
                    entries = await route_store.list()
                    for segment, entry in entries.items():
                        if entry.attach_expires_at and entry.attach_expires_at < now:
                            async with self._routes_lock:
                                connector = self._downstream_routes.pop(segment, None)
                            if connector:
                                await self._safe_stop(connector)
                            await route_store.delete(segment)
                            logger.debug("auto_expired_route", segment=segment)
                    # -----------------------------------

                    # Sleep–with-early-exit: 1-second cadence or until stop requested.
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=1.0)
                    except asyncio.TimeoutError:
                        pass  # timeout → loop again and do janitor work

        except asyncio.CancelledError:
            logger.debug("[RoutingNode] Janitor loop cancelled")
        except Exception:  # pragma: no cover – defensive
            logger.exception("[RoutingNode] Janitor loop error – exiting")
        finally:
            logger.debug("[RoutingNode] Janitor loop exited")

    async def register_peer_route(self, segment: str, route: FameConnector) -> None:
        async with self._routes_lock:
            self._peer_routes[segment] = route
        logger.debug("registered_peer_route", route=segment)

    async def unregister_peer_route(self, segment: str) -> None:
        async with self._routes_lock:
            self._peer_routes.pop(segment, None)

    async def _remove_peer_route(self, segment: str, *, stop: bool = True) -> None:
        await self.remove_route(segment, self._peer_routes, self._peer_route_store, stop=stop)
