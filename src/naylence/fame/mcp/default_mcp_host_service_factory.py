from typing import Any, Optional

from naylence.fame.core import (
    FameService,
    FameServiceFactory,
)


class DefaultMCPHostServiceFactory(FameServiceFactory):
    async def create(self, config: Optional[Any] = None, **kwargs: Any) -> FameService:
        from naylence.fame.mcp.default_mcp_host_service import DefaultMCPHostService

        return DefaultMCPHostService(**kwargs)
