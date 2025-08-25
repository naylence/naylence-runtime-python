# # tests/naylence/test_integration_mcp_service.py

# import asyncio
# import json
# import threading
# import time

# import pytest
# import uvicorn
# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import StreamingResponse
# from pydantic import AnyUrl

# from naylence.fame.service.default_mcp_service import DefaultMCPService
# from naylence.fame.service.mcp_service import APIKeyAuth

# # ─── 1) In-process stub server ─────────────────────────────────────────


# @pytest.fixture(scope="session")
# def real_mcp_endpoint(free_tcp_port_factory):
#     app = FastAPI()
#     subscriptions: set[str] = set()

#     # JSON-RPC & SSE all live under /mcp/
#     @app.post("/mcp/")
#     async def rpc(request: Request):
#         body = await request.json()
#         method = body.get("method")
#         _id = body.get("id")

#         if method == "initialize":
#             # reply with all required InitializeResult fields
#             return {
#                 "jsonrpc": "2.0",
#                 "id": _id,
#                 "result": {
#                     "protocolVersion": "2025-03-26",
#                     "capabilities": {
#                         "roots": {"listChanged": True},
#                         "sampling": {"min": 0, "max": 0},
#                     },
#                     "serverInfo": {
#                         "name": "TestServer",
#                         "version": "0.1.0",
#                         "implementation": {"name": "TestServer", "version": "0.1.0"},
#                     },
#                 },
#             }

#         elif method == "resources/subscribe":
#             uri = body["params"]["uri"]
#             subscriptions.add(uri)
#             return {"jsonrpc": "2.0", "id": _id, "result": None}

#         elif method == "resources/unsubscribe":
#             uri = body["params"]["uri"]
#             subscriptions.discard(uri)
#             return {"jsonrpc": "2.0", "id": _id, "result": None}

#         # unknown JSON-RPC
#         raise HTTPException(
#             status_code=200,
#             detail={
#                 "jsonrpc": "2.0",
#                 "id": _id,
#                 "error": {"code": -32601, "message": "Method not found"},
#             },
#         )

#     @app.get("/mcp/")
#     async def sse(request: Request):
#         async def streamer():
#             # wait until subscribe() is called
#             while not subscriptions:
#                 await asyncio.sleep(0.01)
#             # emit an SSE “resourceUpdated” event per URI
#             for uri in list(subscriptions):
#                 payload = json.dumps({"uri": uri, "update": {"foo": "bar"}})
#                 yield "event: resourceUpdated\r\n"
#                 yield f"data: {payload}\r\n\r\n"

#         return StreamingResponse(
#             streamer(),
#             media_type="text/event-stream",
#             headers={"Connection": "keep-alive"},
#         )

#     # start on a random free port
#     port = free_tcp_port_factory()
#     thread = threading.Thread(
#         target=lambda: uvicorn.run(
#             app,
#             host="127.0.0.1",
#             port=port,
#             log_level="warning",
#         ),
#         daemon=True,
#     )
#     thread.start()
#     time.sleep(0.1)  # give Uvicorn a moment to bind

#     yield f"http://127.0.0.1:{port}/mcp/"


# # ─── 2) DefaultMCPService pointed at our stub ──────────────────────────────


# @pytest.fixture
# async def mcp_service_with_real(real_mcp_endpoint):
#     svc = DefaultMCPService()
#     await svc.register_server(
#         name="real",
#         endpoint=real_mcp_endpoint,
#         auth=APIKeyAuth("dummy-key"),
#     )
#     svc._default_server = "real"

#     received: list[tuple[str, dict]] = []

#     async def handler(uri: AnyUrl, update: dict):
#         received.append((str(uri), update))

#     svc._sessions["real"].message_handler = handler

#     return svc, received


# # ─── 3) Integration test ────────────────────────────────────────────────


# @pytest.mark.asyncio
# async def test_real_server_roundtrip(mcp_service_with_real):
#     svc, received = mcp_service_with_real
#     uri = "http://example.com/foo"

#     # subscribe → JSON-RPC + then SSE on the same connection
#     await svc.subscribe_resource("alice@/", uri)

#     # wait for the “resourceUpdated” event to arrive
#     await asyncio.sleep(0.2)

#     assert received == [
#         (uri, {"foo": "bar"}),
#     ]

#     # now unsubscribe (no hanging)
#     await svc.unsubscribe_resource("alice@/", uri)
