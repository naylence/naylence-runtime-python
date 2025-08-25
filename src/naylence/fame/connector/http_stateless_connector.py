from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from naylence.fame.connector.base_async_connector import BaseAsyncConnector
from naylence.fame.core import AuthorizationContext, FameChannelMessage, FameEnvelope
from naylence.fame.errors.errors import FameTransportClose
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

# Sentinel object to signal shutdown
_SHUTDOWN_SENTINEL = object()


class HttpStatelessConnector(BaseAsyncConnector):
    """
    Outbound = POST per envelope • Inbound = FastAPI pushes bytes

    This connector implements a stateless HTTP half-duplex communication pattern:
    - Outbound messages are sent via HTTP POST requests
    - Inbound messages are received via FastAPI route handlers that push bytes to a queue
    """

    def __init__(
        self,
        *,
        url: str,
        max_queue: int = 1024,
        auth_header: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._url = url
        self._auth_header = auth_header  # Will be set by attach refresh loop
        self._http = httpx.AsyncClient(timeout=None)
        self._recv_q: asyncio.Queue[bytes | FameEnvelope | FameChannelMessage | object] = asyncio.Queue(
            maxsize=max_queue
        )
        self._is_shutting_down = False
        self._authorization_context: Optional[AuthorizationContext] = None

    # ── BaseAsyncConnector hooks ───────────────────────────────
    async def _transport_send_bytes(self, data: bytes) -> None:
        """Send bytes via HTTP POST to the outbox URL."""
        headers = {
            "Content-Type": "application/octet-stream",
        }
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        try:
            response = await self._http.post(
                self._url,
                content=data,
                headers=headers,
            )
            if response.status_code >= 300:
                logger.error(
                    "http_request_failed",
                    exc_info=True,
                    url=self._url,
                    status_code=response.status_code,
                    response_text=response.text,
                )
                raise FameTransportClose(response.status_code, f"{response.status_code} {response.text}")
        except httpx.RequestError as e:
            logger.error("http_request_failed", exc_info=True, url=self._url)
            raise FameTransportClose(1006, f"HTTP request failed: {e}") from e

    async def _transport_receive(self) -> bytes | FameEnvelope | FameChannelMessage:
        """Receive bytes from the internal queue (populated by FastAPI router)."""
        item = await self._recv_q.get()
        if item is _SHUTDOWN_SENTINEL:
            # Shutdown was requested, re-raise as CancelledError to stop the receive loop
            raise asyncio.CancelledError("Connector shutdown requested")
        return item  # type: ignore

    async def _transport_close(self, code: int, reason: str) -> None:
        """Close the HTTP client and cleanup resources."""
        logger.debug("connector_shutting_down", code=code, reason=reason)

        # Signal shutdown to the receive loop
        self._is_shutting_down = True
        try:
            self._recv_q.put_nowait(_SHUTDOWN_SENTINEL)
            logger.debug("shutdown_sentinel_sent")
        except asyncio.QueueFull:
            # If the queue is full, the receive loop will be cancelled anyway
            logger.debug("skipped_shutdown_sentinel", reason="queue full")

        await self._http.aclose()
        logger.debug("http_client_closed", url=self._url)

    # ── Called by the FastAPI router ───────────────────────────
    async def push_to_receive(self, raw_or_envelope: bytes | FameEnvelope | FameChannelMessage) -> None:
        """
        Push raw bytes to the receive queue.
        This method is called by the FastAPI router when receiving inbound messages.

        Args:
            raw: Raw envelope bytes to be processed

        Raises:
            asyncio.QueueFull: If the receive queue is full
        """
        if self._is_shutting_down:
            # This connector is shutting down, ignore the message
            # This can happen during reconnection when there's a race condition
            # between the old connector shutdown and the HTTP listener getting
            # updated connector references
            return

        try:
            self._recv_q.put_nowait(raw_or_envelope)
        except asyncio.QueueFull:
            # Let the caller handle the queue full condition
            raise

    def set_auth_header(self, auth_header: str) -> None:
        """Set the authorization header for outbound requests."""
        self._auth_header = auth_header

    @property
    def remaining_credits(self) -> int:
        """Return remaining flow control credits for status reporting."""
        if hasattr(self._flow_ctrl, "get_credits"):
            return self._flow_ctrl.get_credits(self._connector_flow_id)
        return 0

    @property
    def queue_space(self) -> int:
        """Return available space in the receive queue."""
        return self._recv_q.maxsize - self._recv_q.qsize()

    @property
    def authorization_context(self) -> Optional[AuthorizationContext]:
        """Return the current authorization context."""
        return self._authorization_context

    @authorization_context.setter
    def authorization_context(self, context: Optional[AuthorizationContext]) -> None:
        """Set the authorization context for this connector."""
        self._authorization_context = context
        # TODO: compare the content
