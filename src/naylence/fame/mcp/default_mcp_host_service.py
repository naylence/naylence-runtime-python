from __future__ import annotations

import asyncio
import os
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Union,
)

from pydantic import AnyUrl

from naylence.fame.core import (
    DataFrame,
    FameAddress,
    SenderProtocol,
    create_fame_envelope,
    make_fame_address,
)
from naylence.fame.mcp.mcp_host_service import APIKeyAuth, MCPAuthSpec, MCPHostService
from naylence.fame.mcp.mcp_host_session import MCPHostSession
from naylence.fame.util.envelope_context import current_trace_id
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class _MCPSessionEntry:
    """Wraps the SDK session + last-used timestamp."""

    def __init__(
        self,
        endpoint: str,
        message_handler: Callable[[AnyUrl, Any], Awaitable[None]],
        auth: MCPAuthSpec | None,
    ):
        self.endpoint = endpoint
        self.message_handler = message_handler
        self.auth = auth
        self.sdk: Optional[MCPHostSession] = None
        self.last_used: datetime = datetime.now(timezone.utc)

    async def _new_sdk(self) -> MCPHostSession:
        from naylence.fame.mcp.default_mcp_host_session import DefaultMCPHostSession

        sdk = DefaultMCPHostSession(endpoint=self.endpoint, message_handler=self.message_handler)
        await sdk.initialize()
        return sdk

    async def get(self) -> MCPHostSession:
        if not self.sdk:
            self.sdk = await self._new_sdk()
        self.last_used = datetime.now(timezone.utc)
        return self.sdk

    async def close(self) -> None:
        if self.sdk:
            try:
                await self.sdk.aclose()
            finally:
                self.sdk = None


class DefaultMCPHostService(MCPHostService):
    IDLE_TIMEOUT = timedelta(minutes=30)
    MAX_SESSIONS = 20

    def __init__(
        self,
        sender: SenderProtocol | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ):
        if sender:
            self._sender = sender
        else:
            from naylence.fame.node.node import get_node

            self._sender = get_node().deliver

        self._loop = loop
        if not self._loop:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                # No running loop, create a new one
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        self._sessions: OrderedDict[str, _MCPSessionEntry] = OrderedDict()
        self._default_server: Optional[str] = None  # ContextVar alt possible

        self._evict_task = self._loop.create_task(self._evict_idle(), name="default mcp service evict task")
        logger.debug("created_evict_idle_task", task=self._evict_task)

        # holds FameAddress watchers per URI
        self._subscribers: Dict[AnyUrl, Set[FameAddress]] = {}
        # remembers which URIs we’ve told the server about
        self._subscribed_uris: Set[str] = set()
        # session.message_handler was set up at session creation

        # preload aliases from env like MCP_SERVER_acme=endpoint|api_key:XXX
        self._load_env_aliases()

        self._closed: asyncio.Event = asyncio.Event()

    # ─── public façade ────────────────────────────────────────────────────
    async def list_tools(self, server: str | None = None) -> List[dict[str, Any]]:
        sdk = await self._sdk(server)
        return (await sdk.list_tools())["tools"]

    async def call_tool(
        self,
        name: str,
        args: Optional[dict[str, Any]] = None,
        *,
        server: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        sdk = await self._sdk(server)
        return await sdk.call_tool(name, args or {})

    async def list_templates(self, server: str | None = None) -> List[str]:
        sdk = await self._sdk(server)
        return (await sdk.list_templates())["templates"]

    async def list_resources(
        self, server: str | None = None, cursor: Optional[str] = None
    ) -> Dict[str, Any]:
        sdk = await self._sdk(server)
        res = await sdk.list_resources(cursor)
        return {"resources": res["resources"], "cursor": res["cursor"]}

    async def list_resource_templates(
        self, server: str | None = None, cursor: Optional[str] = None
    ) -> Dict[str, Any]:
        sdk = await self._sdk(server)
        templ = await sdk.list_resource_templates(cursor)
        return {"templates": templ["templates"], "cursor": templ["cursor"]}

    async def read_resource(self, uri: str, server: str | None = None) -> Union[str, bytes]:
        sdk = await self._sdk(server)
        return await sdk.read_resource(AnyUrl(uri))

    async def subscribe_resource(self, subscriber: FameAddress, uri: str, server: str | None = None):
        # register local watcher
        subs = self._subscribers.setdefault(AnyUrl(uri), set())
        subs.add(subscriber)

        # first time for this URI? call the RPC
        if uri not in self._subscribed_uris:
            await (await self._sdk(server)).subscribe_resource(AnyUrl(uri))
            self._subscribed_uris.add(uri)

    async def unsubscribe_resource(self, subscriber: FameAddress, uri: str, server: str | None = None):
        subs = self._subscribers.get(AnyUrl(uri))
        if not subs or subscriber not in subs:
            return
        subs.remove(subscriber)

        # no watchers left? tell the server and clean up
        if not subs:
            await (await self._sdk(server)).unsubscribe_resource(AnyUrl(uri))
            self._subscribed_uris.remove(uri)
            self._subscribers.pop(AnyUrl(uri))

    async def list_prompts(self, server: str | None = None, cursor: Optional[str] = None) -> Dict[str, Any]:
        sdk = await self._sdk(server)
        rp = await sdk.list_prompts(cursor)
        return {"prompts": rp["prompts"], "cursor": rp["cursor"]}

    async def get_prompt(
        self,
        name: str,
        arguments: Dict[str, str] | None = None,
        server: str | None = None,
    ) -> List[Any]:
        sdk = await self._sdk(server)
        return await sdk.get_prompts(name, arguments or {})

    async def complete(
        self,
        ref: Any,
        argument: Dict[str, str],
        server: str | None = None,
    ) -> Dict[str, Any]:
        sdk = await self._sdk(server)
        comp = (await sdk.complete(ref, argument))["completion"]
        return {"values": comp.values, "total": comp.total, "hasMore": comp.hasMore}

    # ─── RPC entrypoint ────────────────────────────────────────────────────
    async def handle_rpc_request(self, method: str, params: Any) -> Any:
        # —————————————————————————————————————————————————————————————————————
        # 1) Normalize “params” into positional args + keyword args
        # —————————————————————————————————————————————————————————————————————
        if isinstance(params, dict) and "args" in params and "kwargs" in params:
            wrapper_args = params["args"] or []
            wrapper_kwargs = params["kwargs"] or {}
        else:
            wrapper_args = []
            wrapper_kwargs = params or {}

        # helper to pull by name or by position
        def get(name: str, pos: Optional[int] = None, default=None):
            if name in wrapper_kwargs:
                return wrapper_kwargs[name]
            if pos is not None and pos < len(wrapper_args):
                return wrapper_args[pos]
            return default

        # convenience for server override
        server = get("server", pos=0, default=None)

        # tools
        if method == "list_tools":
            return await self.list_tools(server=server)

        if method == "call_tool":
            name = get("name", pos=0)
            if not isinstance(name, str):
                raise ValueError(f"Invalid rpc method name: {name}")
            args = get("args", pos=1, default={})
            return await self.call_tool(name, args, server=server)

        # templates
        if method == "list_templates":
            return await self.list_templates(server=server)

        # resource pages
        if method == "list_resources":
            cursor = get("cursor", pos=1)
            return await self.list_resources(server=server, cursor=cursor)

        if method == "list_resource_templates":
            cursor = get("cursor", pos=1)
            return await self.list_resource_templates(server=server, cursor=cursor)

        # resource ops
        if method == "read_resource":
            uri = get("uri", pos=0)
            if not uri:
                raise ValueError(f"Invalid uri : {uri}")
            return await self.read_resource(uri, server=server)

        if method == "subscribe_resource":
            s = get("subscriber", pos=0)
            if not s:
                raise ValueError(f"Invalid subscriber : {s}")
            subscriber = make_fame_address(s)
            uri = get("uri", pos=1)
            if not uri:
                raise ValueError(f"Invalid uri : {uri}")
            return await self.subscribe_resource(
                subscriber=subscriber,
                uri=uri,
                server=server,
            )

        if method == "unsubscribe_resource":
            s = get("subscriber", pos=0)
            if not s:
                raise ValueError(f"Invalid subscriber : {s}")
            subscriber = make_fame_address(s)
            uri = get("uri", pos=1)
            if not uri:
                raise ValueError(f"Invalid uri : {uri}")
            return await self.unsubscribe_resource(
                subscriber=subscriber,
                uri=uri,
                server=server,
            )

        # prompts
        if method == "list_prompts":
            cursor = get("cursor", pos=1)
            return await self.list_prompts(server=server, cursor=cursor)

        if method == "get_prompt":
            name = get("name", pos=0)
            if not isinstance(name, str):
                raise ValueError(f"Invalid name: {name}")
            arguments = get("arguments", pos=1, default={})
            return await self.get_prompt(name, arguments, server=server)

        # completions
        if method == "complete":
            ref = get("ref", pos=0)
            argument = get("argument", pos=1, default={})
            if argument is None:
                raise ValueError(f"Invalid argument: {argument}")
            return await self.complete(ref, argument, server=server)

        # admin
        if method == "register_server":
            name = get("name", pos=0)
            if not isinstance(name, str):
                raise ValueError(f"Invalid name: {name}")
            endpoint = get("endpoint", pos=1)
            if not isinstance(endpoint, str):
                raise ValueError(f"Invalid name: {endpoint}")
            auth = get("auth", pos=2)
            await self.register_server(name, endpoint, auth)
            return None

        if method == "unregister_server":
            name = get("name", pos=0)
            if not isinstance(name, str):
                raise ValueError(f"Invalid name: {name}")
            await self.unregister_server(name)
            return None

        # generic __call__
        if method == "__call__":
            name = get("name", pos=0)
            if not isinstance(name, str):
                raise ValueError(f"Invalid name: {name}")
            args = get("args", pos=1, default={})
            return await self.call_tool(name, args, server=server)

        raise AttributeError(f"Unknown MCP RPC method: {method!r}")

    # ───── dynamic server registry ─────────────────────────────────────

    async def register_server(
        self,
        name: str,
        endpoint: str,
        auth: MCPAuthSpec | None = None,
    ) -> None:
        if name in self._sessions:
            await self.unregister_server(name)
        self._sessions[name] = _MCPSessionEntry(endpoint, self._on_mcp_notification, auth)

    async def unregister_server(self, name: str) -> None:
        entry = self._sessions.pop(name, None)
        if entry:
            await entry.close()

    # ───── context helper ──────────────────────────────────────────────
    @asynccontextmanager
    async def use(self, server: str) -> AsyncGenerator[None, None]:
        prev, self._default_server = self._default_server, server
        try:
            yield
        finally:
            self._default_server = prev

    # ───── internal helpers ────────────────────────────────────────────
    async def _sdk(self, server: str | None) -> MCPHostSession:
        server = server or self._default_server
        if not server:
            raise RuntimeError("No server specified and no default set.")
        entry = self._sessions.get(server)
        if not entry:
            raise KeyError(f"unknown MCP server alias {server!r}")
        sdk = await entry.get()

        # LRU move-to-end
        self._sessions.move_to_end(server)
        if len(self._sessions) > self.MAX_SESSIONS:
            # pop oldest
            old_name, old_entry = self._sessions.popitem(last=False)
            await old_entry.close()
        return sdk

    def _load_env_aliases(self) -> None:
        """
        Env var syntax:
            MCP_SERVER_<ALIAS>=<endpoint>|api_key:<KEY>
            MCP_SERVER_foo=https://mcp.foo.local|api_key:XYZ
        """
        for key, val in os.environ.items():
            if not key.startswith("MCP_SERVER_"):
                continue
            alias = key.removeprefix("MCP_SERVER_").lower()
            endpoint, _, auth_part = val.partition("|")
            if auth_part.startswith("api_key:"):
                api_key = auth_part.removeprefix("api_key:")
                auth: MCPAuthSpec = APIKeyAuth(api_key)
            else:
                # extend as needed
                continue
            # register synchronously; we're in __init__
            self._sessions[alias] = _MCPSessionEntry(endpoint, self._on_mcp_notification, auth)

    # async def _evict_idle(self):
    #     while True:
    #         await asyncio.sleep(self.IDLE_TIMEOUT.total_seconds() / 2)
    #         now = datetime.now(timezone.utc)
    #         for name, entry in list(self._sessions.items()):
    #             if now - entry.last_used > self.IDLE_TIMEOUT:
    #                 await entry.close()
    #                 self._sessions.pop(name, None)

    async def _on_mcp_notification(self, uri: AnyUrl, notification: Any) -> None:
        for addr in self._subscribers.get(uri, ()):
            env = create_fame_envelope(
                trace_id=current_trace_id(),
                to=addr,
                frame=DataFrame(payload={"uri": uri, "update": notification}),
            )
            await self._sender(env)

    async def close(self) -> None:
        """
        Gracefully shut the service down:
        • stop the idle-eviction task
        • close all open SDK sessions
        • mark the service as closed so subsequent calls raise
        """
        if self._closed.is_set():
            return  # idempotent

        self._closed.set()

        # 1) cancel the background task
        if self._evict_task:
            self._evict_task.cancel()
            try:
                await self._evict_task
            except asyncio.CancelledError:
                pass
            finally:
                self._evict_task = None

        # 2) close every cached session
        for name, entry in list(self._sessions.items()):
            try:
                await entry.close()
            finally:
                self._sessions.pop(name, None)

    # make   async with DefaultMCPService(...) as svc:   work
    async def __aenter__(self):  # noqa: D401
        return self

    async def __aexit__(self, _exc_type, _exc, _tb):  # noqa: D401
        await self.close()

    async def _evict_idle(self):
        try:
            while not self._closed.is_set():
                try:
                    # sleep-until-closed, but wake ourselves halfway through
                    await asyncio.wait_for(
                        self._closed.wait(),
                        timeout=self.IDLE_TIMEOUT.total_seconds() / 2,
                    )
                    # closed → drop straight out of the loop
                    continue
                except asyncio.TimeoutError:
                    # timeout → run an eviction pass
                    now = datetime.now(timezone.utc)
                    for name, entry in list(self._sessions.items()):
                        if now - entry.last_used > self.IDLE_TIMEOUT:
                            await entry.close()
                            self._sessions.pop(name, None)
        except asyncio.CancelledError:
            # graceful shutdown
            pass
