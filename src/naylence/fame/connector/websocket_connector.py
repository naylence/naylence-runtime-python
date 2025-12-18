from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Optional

import websockets

from naylence.fame.connector.base_async_connector import BaseAsyncConnector
from naylence.fame.core import AuthorizationContext
from naylence.fame.errors.errors import FameTransportClose
from naylence.fame.util import logging

# ---------------------------------------------------------------------------
# Optional FastAPI import – safe when FastAPI isn’t installed
# ---------------------------------------------------------------------------
try:  # pragma: no cover
    from fastapi import WebSocket as _FastAPIWebSocket
    from fastapi import WebSocketDisconnect as _FastAPIWebSocketDisconnect
    from fastapi.websockets import WebSocketState as _FastAPIWebSocketState
except ModuleNotFoundError:  # FastAPI not installed
    _FastAPIWebSocket = None  # type: ignore
    _FastAPIWebSocketDisconnect = ()  # type: ignore
    _FastAPIWebSocketState = None  # type: ignore

# For type-checkers (they run in a virtual env where FastAPI *is* present)
if TYPE_CHECKING:  # pragma: no cover
    from fastapi import WebSocket as _FastAPIWebSocket
    from fastapi import WebSocketDisconnect as _FastAPIWebSocketDisconnect
    from fastapi.websockets import WebSocketState as _FastAPIWebSocketState


logger = logging.getLogger(__name__)


class WebSocketConnector(BaseAsyncConnector):
    """
    A thin transport adapter that can work with either:

    • `websockets.client.WebSocketClientProtocol` (the std-lib style)
    • `fastapi.WebSocket` (server side)

    FastAPI is treated as an **optional** dependency.  If FastAPI is not
    installed, only the std-lib websocket path is available.
    """

    def __init__(
        self,
        websocket: Any,
        *,
        authorization_context: Optional[AuthorizationContext] = None,
        drain_timeout: float = 0.1,
    ):
        super().__init__(drain_timeout=drain_timeout)

        self.websocket = websocket
        self._is_fastapi = _FastAPIWebSocket is not None and isinstance(websocket, _FastAPIWebSocket)

        self._authorization_context: Optional[AuthorizationContext] = authorization_context

    # --------------------------------------------------------------------- #
    # low-level send/recv/close                                              #
    # --------------------------------------------------------------------- #
    async def _transport_send_bytes(self, data: bytes) -> None:
        try:
            if self._is_fastapi:
                await self.websocket.send_bytes(data)
            else:
                await self.websocket.send(data)
        except (_FastAPIWebSocketDisconnect, websockets.ConnectionClosed) as ws:  # type: ignore
            raise FameTransportClose(ws.code, getattr(ws, "reason", "") or "peer closed")

    async def _transport_receive(self) -> bytes:
        """
        Receive bytes from the websocket with enhanced error handling and cancellation safety.
        """
        try:
            # Validate websocket object before attempting to receive
            if self.websocket is None:
                raise FameTransportClose(1006, "WebSocket object is None")

            # Use a timeout to prevent hanging during shutdown scenarios
            # Increased to 3600s to match Uvicorn keep-alive and prevent idle disconnects
            receive_timeout = 30.0

            if self._is_fastapi:
                # Check if receive_bytes method exists and is callable
                receive_method = getattr(self.websocket, "receive_bytes", None)

                if not receive_method or not callable(receive_method):
                    raise FameTransportClose(1006, "FastAPI WebSocket receive_bytes method not available")

                result = self.websocket.receive_bytes()
                # logger.debug("fastapi_receive_result_type", result_type=type(result).__name__)

                # Additional validation to ensure we have an awaitable
                if not hasattr(result, "__await__") and not asyncio.iscoroutine(result):
                    logger.error(
                        "fastapi_receive_not_awaitable",
                        result_type=type(result).__name__,
                        result_str=str(result)[:100],
                    )
                    raise FameTransportClose(
                        1006,
                        f"FastAPI receive_bytes returned non-awaitable: {type(result)}",
                    )

                # Use asyncio.wait_for to add timeout protection and better cancellation handling
                try:
                    return await asyncio.wait_for(result, timeout=receive_timeout)
                except asyncio.TimeoutError:
                    # Check if we're being cancelled during timeout
                    current_task = asyncio.current_task()
                    if current_task and current_task.cancelled():
                        raise asyncio.CancelledError("Receive timeout during task cancellation")
                    raise FameTransportClose(1006, "FastAPI receive_bytes timed out")
                except asyncio.CancelledError:
                    logger.debug("fastapi_receive_cancelled")
                    raise
                except Exception as e:
                    # Check if this is the known WebSocket shutdown race condition
                    # (normal during task cancellation)
                    if "await wasn't used with future" in str(e):
                        logger.debug(
                            "websocket_shutdown_race_condition_handled",
                            note="Normal WebSocket close timing - converting to cancellation",
                            websocket_state=getattr(self.websocket, "client_state", "unknown"),
                        )
                        # Convert to cancellation error if this happened during shutdown
                        current_task = asyncio.current_task()
                        if current_task and current_task.cancelled():
                            raise asyncio.CancelledError(
                                "Converted await future error during cancellation"
                            ) from e
                    raise
            else:
                # Check if recv method exists and is callable
                recv_method = getattr(self.websocket, "recv", None)

                if not recv_method or not callable(recv_method):
                    raise FameTransportClose(1006, "WebSocket recv method not available")

                result = self.websocket.recv()

                # Additional validation to ensure we have an awaitable
                if not hasattr(result, "__await__") and not asyncio.iscoroutine(result):
                    logger.error(
                        "websockets_recv_not_awaitable",
                        result_type=type(result).__name__,
                        result_str=str(result)[:100],
                    )
                    raise FameTransportClose(1006, f"WebSocket recv returned non-awaitable: {type(result)}")

                # Use asyncio.wait_for for timeout protection and better cancellation handling
                try:
                    return await asyncio.wait_for(result, timeout=receive_timeout)
                except asyncio.TimeoutError:
                    # Check if we're being cancelled during timeout
                    current_task = asyncio.current_task()
                    if current_task and current_task.cancelled():
                        raise asyncio.CancelledError("Receive timeout during task cancellation")
                    raise FameTransportClose(1006, "WebSocket recv timed out")
                except asyncio.CancelledError:
                    logger.debug("websockets_recv_cancelled")
                    raise
                except Exception as e:
                    # Check if this is the problematic "await wasn't used with future" during cancellation
                    if "await wasn't used with future" in str(e):
                        logger.warning(
                            "websockets_recv_await_future_during_cancellation",
                            error=str(e),
                            websocket_state=getattr(self.websocket, "state", "unknown"),
                        )
                        # Convert to cancellation error if this happened during shutdown
                        current_task = asyncio.current_task()
                        if current_task and current_task.cancelled():
                            raise asyncio.CancelledError(
                                "Converted await future error during cancellation"
                            ) from e
                    raise
        except TypeError as e:
            if "await wasn't used with future" in str(e):
                logger.debug(
                    "websocket_shutdown_race_condition_detected",
                    websocket_type=type(self.websocket).__name__,
                    is_fastapi=self._is_fastapi,
                    note="Normal WebSocket close timing during shutdown",
                )

                # Check if current task is being cancelled - this is the expected case
                current_task = asyncio.current_task()
                if current_task and current_task.cancelled():
                    logger.debug(
                        "websocket_cancelled_during_receive",
                        task_name=current_task.get_name(),
                        note="Normal shutdown sequence",
                    )
                    raise asyncio.CancelledError("WebSocket cancelled during receive operation") from e

                # Try to get more info about what we're trying to await
                if self._is_fastapi:
                    try:
                        problematic_result = self.websocket.receive_bytes()
                        logger.error(
                            "fastapi_problematic_result",
                            result_type=type(problematic_result).__name__,
                            result_value=str(problematic_result)[:200],
                        )
                    except Exception as debug_e:
                        logger.error("fastapi_debug_error", error=str(debug_e))
                else:
                    try:
                        problematic_result = self.websocket.recv()
                        logger.error(
                            "websockets_problematic_result",
                            result_type=type(problematic_result).__name__,
                            result_value=str(problematic_result)[:200],
                        )
                    except Exception as debug_e:
                        logger.error("websockets_debug_error", error=str(debug_e))
            raise
        except (_FastAPIWebSocketDisconnect, websockets.ConnectionClosed) as ws:  # type: ignore
            raise FameTransportClose(ws.code, getattr(ws, "reason", "") or "peer closed")

    async def _transport_close(self, code: int, reason: str) -> None:
        if self._is_fastapi:
            # FastAPI's WebSocket has explicit state tracking
            if self.websocket.client_state == _FastAPIWebSocketState.CONNECTED:  # type: ignore
                try:
                    await self.websocket.close(code=code, reason=reason)  # type: ignore
                except Exception as e:  # type: ignore
                    logger.error("websocket_close_failed", error=e, exc_info=True)
                    # raise
        else:
            await self.websocket.close(code=code, reason=reason)

    @property
    def authorization_context(self) -> Optional[AuthorizationContext]:
        """Return the current authorization context."""
        return self._authorization_context

    @authorization_context.setter
    def authorization_context(self, context: Optional[AuthorizationContext]) -> None:
        """Set the authorization context for this connector."""
        self._authorization_context = context
