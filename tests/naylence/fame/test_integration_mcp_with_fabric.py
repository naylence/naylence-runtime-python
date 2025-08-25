from typing import Any, cast

import pytest

from naylence.fame.core import MCP_HOST_CAPABILITY, FameFabric
from naylence.fame.mcp.default_mcp_host_service import DefaultMCPHostService
from naylence.fame.mcp.mcp_host_service import MCPHostService
from naylence.fame.util.logging import enable_logging

enable_logging(log_level="TRACE")


class DummySDK:
    """A stand-in for the real MCPSDKSession that simply echoes back."""

    async def initialize(self) -> None:
        # no-op initialize
        return

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # echo back both name and args
        return {"tool": name, "args": arguments}


@pytest.mark.asyncio
async def test_call_tool_via_fabric(monkeypatch):
    # 1) Patch DefaultMCPService._sdk so it returns our DummySDK always
    async def fake_sdk(self, server: str | None = None) -> DummySDK:
        return DummySDK()

    monkeypatch.setattr(DefaultMCPHostService, "_sdk", fake_sdk)

    # 2) Create the in-process fabric and register the MCP service
    async with FameFabric.create() as fabr:
        # set_fame_fabric(fabric)
        mcp_service = DefaultMCPHostService(fabr.send)
        await fabr.serve(mcp_service, "mcp")  # serves RPC at “mcp”

        # 3) Resolve the service by its capability
        proxy = fabr.resolve_service_by_capability(MCP_HOST_CAPABILITY)

        mcp = cast(MCPHostService, proxy)

        # 4) Call the tool over RPC
        result = await mcp.call_tool(name="add_numbers", args={"x": 2, "y": 3})
        assert result == {"tool": "add_numbers", "args": {"x": 2, "y": 3}}
