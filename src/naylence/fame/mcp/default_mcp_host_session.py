from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

import httpx
from pydantic import AnyUrl

from mcp.client.session import ClientSession as MCPClientSession
from mcp.client.session import SamplingFnT
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.session import RequestResponder
from mcp.types import (
    BlobResourceContents,
    ClientResult,
    PromptMessage,
    ResourceUpdatedNotification,
    ServerNotification,
    ServerRequest,
    TextResourceContents,
)
from naylence.fame.mcp.mcp_host_session import MCPHostSession


class DefaultMCPHostSession(MCPHostSession):
    """
    Full-featured wrapper around the MCP Python SDK's ClientSession,
    now including resources, templates, prompts, and completions.
    """

    def __init__(
        self,
        endpoint: str,
        message_handler: Callable[[AnyUrl, Any], Awaitable[None]],
        auth: Optional[httpx.Auth] = None,
        read_timeout_seconds: Optional[timedelta] = None,
        sampling_callback: Optional[SamplingFnT] = None,
    ):
        self.endpoint = endpoint
        self.auth = auth
        self.read_timeout_seconds = read_timeout_seconds
        self.sampling_callback = sampling_callback

        self._message_handler = message_handler
        self._stream_ctx = None
        self._client_ctx = None
        self._session = None  # type: Optional[MCPClientSession]

    async def _start(self) -> None:
        # choose transport
        if self.endpoint.startswith(("http://", "https://")):
            self._stream_ctx = streamablehttp_client(self.endpoint, auth=self.auth)
        else:
            params = StdioServerParameters(command=self.endpoint, args=[], env=None)
            self._stream_ctx = stdio_client(params)

        enter = await self._stream_ctx.__aenter__()  # always at least (read, write)
        read_stream, write_stream = enter[0], enter[1]

        self._client_ctx = MCPClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=self.read_timeout_seconds,
            sampling_callback=self.sampling_callback,
            message_handler=self._internal_message_handler,
        )
        self._session = await self._client_ctx.__aenter__()
        await self._session.initialize()

    async def initialize(self) -> None:
        if not self._session:
            await self._start()

    async def aclose(self) -> None:
        if self._client_ctx:
            await self._client_ctx.__aexit__(None, None, None)
            self._session = None
        if self._stream_ctx:
            await self._stream_ctx.__aexit__(None, None, None)
            self._stream_ctx = None

    # --- Message handler

    async def _internal_message_handler(
        self,
        message: RequestResponder[ServerRequest, ClientResult] | ServerNotification | Exception,
    ) -> None:
        if isinstance(message, ServerNotification):
            match message.root:
                case ResourceUpdatedNotification(params=params):
                    uri = params.uri
                    self._message_handler(uri, params)

    # ─── Tools ────────────────────────────────────────────────────────────
    async def list_tools(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        await self.initialize()
        assert self._session
        result = await self._session.list_tools(cursor)  # :contentReference[oaicite:4]{index=4}
        return {"tools": result.tools}

    async def call_tool(self, name: str, args: Dict[str, Any] | None) -> Any:
        await self.initialize()
        assert self._session
        return await self._session.call_tool(name, args)  # :contentReference[oaicite:5]{index=5}

    # ─── Templates ────────────────────────────────────────────────────────
    async def list_templates(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        await self.initialize()
        assert self._session
        resp = await self._session.list_resource_templates(cursor)
        return {"templates": resp.resourceTemplates}

    # ─── Resources ────────────────────────────────────────────────────────
    async def list_resources(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        await self.initialize()
        assert self._session
        resp = await self._session.list_resources(cursor)
        return {"resources": resp.resources, "cursor": resp.nextCursor}

    async def list_resource_templates(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        await self.initialize()
        assert self._session
        resp = await self._session.list_resource_templates(cursor)
        return {"templates": resp.resourceTemplates, "cursor": resp.nextCursor}

    async def read_resource(self, uri: AnyUrl) -> Union[str, bytes]:
        await self.initialize()
        assert self._session
        # ask the SDK for the raw ReadResourceResult
        resp = await self._session.read_resource(AnyUrl(uri))
        # grab the first content entry
        first = resp.contents[0]
        # text‐only resources present a `.text` attribute
        if isinstance(first, TextResourceContents) and hasattr(first, "text"):
            return first.text
        # binary resources present a base64 string on `.data`—decode it
        if isinstance(first, BlobResourceContents) and hasattr(first, "data"):
            return base64.b64decode(first.blob)
        raise RuntimeError(f"Unexpected resource content: {first}")

    async def subscribe_resource(self, uri: AnyUrl) -> None:
        await self.initialize()
        assert self._session
        await self._session.subscribe_resource(AnyUrl(uri))

    async def unsubscribe_resource(self, uri: AnyUrl) -> None:
        await self.initialize()
        assert self._session
        await self._session.unsubscribe_resource(AnyUrl(uri))

    # ─── Prompts & Completions ─────────────────────────────────────────────
    async def list_prompts(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        await self.initialize()
        assert self._session
        resp = await self._session.list_prompts(cursor)
        return {"prompts": resp.prompts, "cursor": resp.nextCursor}

    async def get_prompts(
        self,
        name: str,
        arguments: Dict[str, str] | None = None,
    ) -> List[PromptMessage]:
        await self.initialize()
        assert self._session
        resp = await self._session.get_prompt(name, arguments or {})
        return resp.messages

    async def complete(
        self,
        ref: Any,
        argument: Dict[str, str],
    ) -> Dict[str, Any]:
        # Ensure the MCP session is up
        await self.initialize()
        assert self._session

        # Perform the completion/complete RPC
        resp = await self._session.complete(ref, argument)

        # Extract the 'completion' object per the spec
        comp = resp.completion

        # Return a plain dict that agents can consume:
        return {
            "values": comp.values,  # List[str]
            "total": comp.total,  # Optional[int]
            "hasMore": comp.hasMore,  # bool
        }
