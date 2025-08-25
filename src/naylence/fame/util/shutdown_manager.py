"""
Shutdown manager for graceful cleanup of Fame resources.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Callable, List, Optional

from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class ShutdownManager:
    """
    Manages graceful shutdown of Fame components when the process receives
    termination signals (SIGINT, SIGTERM).
    """

    _instance: ShutdownManager | None = None
    _cleanup_callbacks: List[Callable[[], asyncio.Task]] = []
    _signals_registered = False

    def __init__(self):
        self._cleanup_callbacks = []
        self._signals_registered = False
        self._shutdown_task: Optional[asyncio.Task] = None
        self._shutdown_in_progress = False

    @classmethod
    def get_instance(cls) -> ShutdownManager:
        """Get the singleton shutdown manager instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_cleanup(self, callback: Callable[[], asyncio.Task]) -> None:
        """
        Register a cleanup callback to be called during shutdown.

        Args:
            callback: Async function to call during shutdown
        """
        self._cleanup_callbacks.append(callback)

        # Register signal handlers if not already done
        if not self._signals_registered:
            self._register_signal_handlers()

    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        try:
            # Only register if we're in the main thread
            asyncio.get_running_loop()

            def signal_handler(signum, frame):
                logger.info(f"Received signal {signum}, initiating graceful shutdown")
                # Use ensure_future instead of create_task to avoid potential issues
                # and store the task so it can be awaited properly
                if self._shutdown_task is None or self._shutdown_task.done():
                    self._shutdown_task = asyncio.ensure_future(self._perform_shutdown())

            # Register handlers for common termination signals
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)

            self._signals_registered = True
            # logger.debug("Signal handlers registered for graceful shutdown")

        except Exception as e:
            logger.warning(f"Could not register signal handlers: {e}")

    async def _perform_shutdown(self) -> None:
        """Perform graceful shutdown by calling all registered cleanup callbacks."""
        if self._shutdown_in_progress:
            logger.debug("Shutdown already in progress, skipping duplicate request")
            return

        self._shutdown_in_progress = True
        logger.info("Starting graceful shutdown sequence")

        # Execute all cleanup callbacks
        tasks = []
        for callback in self._cleanup_callbacks:
            try:
                task = callback()
                if asyncio.iscoroutine(task):
                    tasks.append(task)
                elif isinstance(task, asyncio.Task):
                    tasks.append(task)
            except Exception as e:
                logger.error(f"Error creating cleanup task: {e}", exc_info=True)

        # Wait for all cleanup tasks to complete
        if tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=30.0,  # 30 second timeout for cleanup
                )
                logger.info("Graceful shutdown completed")
            except asyncio.TimeoutError:
                logger.warning("Shutdown timeout exceeded, some cleanup may be incomplete")
            except Exception as e:
                logger.error(f"Error during shutdown: {e}", exc_info=True)

        # Clear callbacks after shutdown
        self._cleanup_callbacks.clear()


def register_shutdown_callback(callback: Callable[[], asyncio.Task]) -> None:
    """
    Convenience function to register a shutdown callback.

    Args:
        callback: Async function to call during shutdown
    """
    ShutdownManager.get_instance().register_cleanup(callback)
