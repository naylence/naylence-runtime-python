import asyncio
import threading
import time

import pytest
import pytest_asyncio
import uvicorn
from fastapi import FastAPI, HTTPException, Request

from naylence.fame.core import FameEnvelope
from naylence.fame.mcp import DefaultMCPHostService
from naylence.fame.mcp.mcp_host_service import APIKeyAuth
from naylence.fame.util import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logging.getLogger("naylence").setLevel(logging.TRACE)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)


async def fake_send(envelope: FameEnvelope) -> None: ...


@pytest.fixture(scope="session")
def real_mcp_endpoint(free_tcp_port_factory):
    """
    Spins up a FastAPI app on a random port that implements exactly:
      - POST /mcp/ → JSON-RPC for 'initialize' & 'tools/call'
    """
    app = FastAPI()

    @app.post("/mcp/")
    async def rpc(request: Request):
        body = await request.json()
        method = body.get("method")
        req_id = body.get("id")

        if method == "initialize":
            # Return the full InitializeResult so pydantic accepts it
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {
                        "roots": {"listChanged": False},
                        "sampling": {"min": 0, "max": 0},
                    },
                    "serverInfo": {
                        "name": "TestServer",
                        "version": "0.1.0",
                        "implementation": {"name": "TestServer", "version": "0.1.0"},
                    },
                },
            }

        elif method == "notifications/initialized":
            # Handle the initialized notification - no response needed for notifications
            # Use FastAPI's Response class to return an empty response
            from fastapi import Response

            return Response(status_code=204)  # No Content

        elif method == "tools/list":
            # Handle tools/list request
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "my_tool",
                            "description": "A test tool",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "x": {"type": "integer"},
                                    "y": {"type": "string"},
                                },
                            },
                        }
                    ]
                },
            }

        elif method == "tools/call":
            params = body.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})

            # Echo back a well-formed CallToolResult
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Called {tool_name} with {args}"}],
                    "isError": False,
                    "isStreaming": False,
                },
            }

        # Unknown method → JSON-RPC error
        raise HTTPException(
            status_code=200,
            detail={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "Method not found"},
            },
        )

    # Launch on a random free port
    port = free_tcp_port_factory()
    thread = threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", ws="none"),
        daemon=True,
    )
    thread.start()
    # Give Uvicorn a moment to bind
    time.sleep(0.1)

    return f"http://127.0.0.1:{port}/mcp/"


@pytest_asyncio.fixture
async def mcp_service_with_real(real_mcp_endpoint):
    # Pass fake_send as sender to prevent Node infrastructure initialization
    svc = DefaultMCPHostService(sender=fake_send)
    await svc.register_server(
        name="real",
        endpoint=real_mcp_endpoint,
        auth=APIKeyAuth("dummy-key"),
    )
    svc._default_server = "real"
    try:
        yield svc
    finally:
        # Simplified cleanup - no need for Node infrastructure cleanup
        try:
            # Cancel eviction task
            if hasattr(svc, "_evict_task") and svc._evict_task and not svc._evict_task.done():
                svc._evict_task.cancel()
                try:
                    await svc._evict_task
                except asyncio.CancelledError:
                    pass

            # Close service sessions
            await svc.close()
        except Exception:
            # Ignore cleanup errors during test teardown
            pass


@pytest.mark.asyncio
async def test_call_tool_roundtrip(mcp_service_with_real):
    svc = mcp_service_with_real

    # 1) Invoke via your service façade
    result = await svc.call_tool("my_tool", {"x": 42, "y": "hello"})

    # 2) The stub encoded its reply into a CallToolResult Pydantic model
    #    with one TextContent. Let’s inspect that:
    assert hasattr(result, "content")
    assert len(result.content) == 1

    item = result.content[0]
    # The TextContent model has `.text`
    assert getattr(item, "text") == "Called my_tool with {'x': 42, 'y': 'hello'}"
    # And isError/isStreaming are correct
    assert result.isError is False
    assert result.isStreaming is False
