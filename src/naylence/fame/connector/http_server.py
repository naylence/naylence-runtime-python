from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from fastapi import APIRouter


class HttpServer(ABC):
    """Abstract HTTP server interface for shared server instances."""

    def __init__(self, *, host: str = "0.0.0.0", port: int = 0) -> None:
        self._host = host
        self._port = port

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @abstractmethod
    async def start(self) -> None:
        """Start the HTTP server (idempotent)."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the HTTP server (idempotent)."""
        pass

    # ── Composition ───────────────────────────────────────────────────────────

    @abstractmethod
    def include_router(self, router: APIRouter) -> None:
        """Add a FastAPI router to this server."""
        pass

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def host(self) -> str:
        """Get the advertised host."""
        return self._host

    @property
    def port(self) -> int:
        """Get the advertised port."""
        return self._port

    @property
    def base_url(self) -> str:
        """Get the base URL for this server."""
        return f"http://{self._host}:{self._port}"

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Check if the server is currently running."""
        pass

    @property
    @abstractmethod
    def actual_host(self) -> Optional[str]:
        """Get the actual bound host (after server starts)."""
        pass

    @property
    @abstractmethod
    def actual_port(self) -> Optional[int]:
        """Get the actual bound port (after server starts)."""
        pass

    @property
    def actual_base_url(self) -> Optional[str]:
        """Get the actual base URL (after server starts)."""
        if self.actual_host and self.actual_port:
            return f"http://{self.actual_host}:{self.actual_port}"
        return None
