from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Dict, Optional, Tuple

import uvicorn
from fastapi import APIRouter, FastAPI

from naylence.fame.connector.http_server import HttpServer
from naylence.fame.util.logging import getLogger
from naylence.fame.util.shutdown_manager import register_shutdown_callback

if TYPE_CHECKING:
    pass

logger = getLogger(__name__)

# Global registry for shared server instances
_registry: Dict[Tuple[str, int], DefaultHttpServer] = {}
_registry_lock = asyncio.Lock()
_reference_counts: Dict[Tuple[str, int], int] = {}
_shutdown_registered = False


class DefaultHttpServer(HttpServer):
    """
    Default HTTP server implementation using FastAPI + Uvicorn.

    This server is shared per (host, port) combination to avoid
    creating multiple servers for the same endpoint.
    """

    def __init__(self, *, host: str = "0.0.0.0", port: int = 0) -> None:
        super().__init__(host=host, port=port)

        # FastAPI application
        self._app: FastAPI = FastAPI(
            title="Fame HTTP Server",
            description="Shared HTTP server for Fame transport listeners",
            lifespan=None,
        )

        # Uvicorn server components
        self._uvicorn: Optional[uvicorn.Server] = None
        self._serve_task: Optional[asyncio.Task] = None

        # Server state
        self._started = False
        self._lock = asyncio.Lock()

        # Actual bound address (set after server starts)
        self._actual_host: Optional[str] = None
        self._actual_port: Optional[int] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the Uvicorn server (idempotent)."""
        if self._started:
            return

        async with self._lock:
            if self._started:
                return

            logger.debug("starting_http_server", host=self._host, port=self._port)

            config = uvicorn.Config(
                self._app,
                host=self._host,
                port=self._port,
                lifespan="off",
                log_config=None,
                loop="asyncio",
                access_log=False,
                # Better shutdown handling
                # Set to 1 hour to prevent WebSocket idle disconnections
                timeout_keep_alive=3600,
                timeout_graceful_shutdown=30,
            )

            self._uvicorn = uvicorn.Server(config)
            self._serve_task = asyncio.create_task(self._uvicorn.serve())

            # Wait until the server is bound and ready
            while not self._uvicorn.started:
                await asyncio.sleep(0.01)

            # Give it a bit more time to fully initialize
            await asyncio.sleep(0.1)

            # Extract the actual bound address
            if self._uvicorn.servers:
                sock = self._uvicorn.servers[0].sockets[0]
                self._actual_host = sock.getsockname()[0]
                self._actual_port = sock.getsockname()[1]
            else:
                # Fallback
                self._actual_host = self._host
                self._actual_port = self._port

            self._started = True
            logger.debug("http_server_started", server=self.actual_base_url)

    async def stop(self) -> None:
        """Stop the Uvicorn server (idempotent)."""
        if not self._started:
            return

        async with self._lock:
            if not self._started:
                return

            logger.debug("Stopping HTTP server")

            # Shutdown the server more gracefully
            if self._uvicorn:
                self._uvicorn.should_exit = True

                # Wait for the serve task to complete instead of checking started flag
                if self._serve_task and not self._serve_task.done():
                    try:
                        # Wait for graceful shutdown with timeout
                        await asyncio.wait_for(self._serve_task, timeout=5.0)
                    except asyncio.TimeoutError:
                        logger.warning("HTTP server did not shut down gracefully, forcing shutdown")
                        self._serve_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await self._serve_task
                    except Exception as e:
                        logger.warning(f"Error during HTTP server shutdown: {e}")

                self._serve_task = None

            self._uvicorn = None
            self._started = False
            self._actual_host = None
            self._actual_port = None

            logger.debug("http_server_stopped")

    # ── Composition ───────────────────────────────────────────────────────────

    def include_router(self, router: APIRouter) -> None:
        """Add a FastAPI router to this server."""
        self._app.include_router(router)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Check if the server is currently running."""
        return self._started

    @property
    def actual_host(self) -> Optional[str]:
        """Get the actual bound host (after server starts)."""
        return self._actual_host

    @property
    def actual_port(self) -> Optional[int]:
        """Get the actual bound port (after server starts)."""
        return self._actual_port

    # ── Registry methods ──────────────────────────────────────────────────────

    @classmethod
    async def get_or_create(cls, host: str = "0.0.0.0", port: int = 0) -> DefaultHttpServer:
        """
        Get an existing HTTP server for (host, port) or create and start a new one.

        Args:
            host: Host to bind to
            port: Port to bind to (0 for OS selection)

        Returns:
            Shared HTTP server instance
        """
        global _shutdown_registered

        key = (host, port)
        async with _registry_lock:
            # Register shutdown callback on first server creation
            if not _shutdown_registered:
                register_shutdown_callback(lambda: asyncio.create_task(cls.shutdown_all()))
                _shutdown_registered = True

            server = _registry.get(key)
            if server is None:
                server = DefaultHttpServer(host=host, port=port)
                await server.start()
                _registry[key] = server
                _reference_counts[key] = 1
            else:
                _reference_counts[key] = _reference_counts.get(key, 0) + 1
            return server

    @classmethod
    async def release(cls, host: str = "0.0.0.0", port: int = 0) -> None:
        """
        Release a reference to an HTTP server and stop it if no more references exist.

        Args:
            host: Host that was bound to
            port: Port that was bound to
        """
        key = (host, port)
        async with _registry_lock:
            if key in _reference_counts:
                _reference_counts[key] -= 1
                if _reference_counts[key] <= 0:
                    # No more references, stop and remove the server
                    server = _registry.get(key)
                    if server:
                        logger.debug("stopping_unused_http_server", host=host, port=port)
                        await server.stop()
                        del _registry[key]
                    if key in _reference_counts:
                        del _reference_counts[key]

    @classmethod
    async def shutdown_all(cls) -> None:
        """Stop and clear all registered HTTP servers."""
        async with _registry_lock:
            for server in list(_registry.values()):
                await server.stop()
            _registry.clear()
            _reference_counts.clear()
