from __future__ import annotations

from typing import (
    Any,
    AsyncContextManager,
    Dict,
    List,
    Optional,
    Protocol,
    TypedDict,
    Union,
    cast,
)

from naylence.fame.core import (
    MCP_HOST_CAPABILITY,
    FameAddress,
    FameFabric,
    FameRPCService,
)


class MCPAuthSpec(Protocol):
    """Marker for auth back ends."""


class APIKeyAuth:
    type = "api_key"

    def __init__(self, api_key: str):
        self.api_key = api_key


class ClientCredsAuth:
    type = "client_credentials"

    def __init__(self, token_url: str, client_id: str, client_secret: str):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret


class SubscribeResourceParams(TypedDict):
    uri: str
    subscriber_address: str
    server: str | None


class UnsubscribeResourceParams(TypedDict):
    uri: str
    subscriber_address: str
    server: str | None


class MCPHostService(FameRPCService, Protocol):
    _capabilities = [MCP_HOST_CAPABILITY]

    @property
    def capabilities(self) -> List[str]:
        return MCPHostService._capabilities

    # ─── tools ──────────────────────────────────────────────────────────────
    async def list_tools(self, server: str | None = None) -> List[dict[str, Any]]: ...
    async def call_tool(
        self,
        name: str,
        args: Optional[dict[str, Any]] = None,
        *,
        server: str | None = None,
    ) -> Any: ...

    # ─── templates ──────────────────────────────────────────────────────────
    async def list_templates(self, server: str | None = None) -> List[str]: ...

    # ─── resources ──────────────────────────────────────────────────────────
    async def list_resources(
        self, server: str | None = None, cursor: Optional[str] = None
    ) -> Dict[str, Any]: ...

    async def list_resource_templates(
        self, server: str | None = None, cursor: Optional[str] = None
    ) -> Dict[str, Any]: ...

    async def read_resource(self, uri: str, server: str | None = None) -> Union[str, bytes]: ...

    async def subscribe_resource(self, subscriber: FameAddress, uri: str, server: str | None = None): ...

    async def unsubscribe_resource(self, subscriber: FameAddress, uri: str, server: str | None = None): ...

    # ─── prompts & completions ──────────────────────────────────────────────
    async def list_prompts(
        self, server: str | None = None, cursor: Optional[str] = None
    ) -> Dict[str, Any]: ...

    async def get_prompt(
        self,
        name: str,
        arguments: Optional[Dict[str, str]] = None,
        server: str | None = None,
    ) -> List[Any]: ...

    async def complete(
        self,
        ref: Any,
        argument: Dict[str, str],
        server: str | None = None,
    ) -> Dict[str, Any]: ...

    # ─── admin / ops ────────────────────────────────────────────────────────
    async def register_server(
        self,
        name: str,
        endpoint: str,
        auth: MCPAuthSpec,
    ) -> None: ...

    async def unregister_server(self, name: str) -> None: ...

    # ─── context helper ─────────────────────────────────────────────────────
    def use(self, server: str) -> AsyncContextManager[None]: ...


def mcp_host():
    return cast(
        MCPHostService,
        FameFabric.current().resolve_service_by_capability(MCP_HOST_CAPABILITY),
    )
