from __future__ import annotations

from typing import Any, Optional

from naylence.fame.node.factory_commons import make_common_opts
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_like_factory import NodeLikeFactory
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class NodeFactory(NodeLikeFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[FameNodeConfig | dict[str, Any]] = None,
        **_: Any,
    ) -> FameNode:
        cfg = config or FameNodeConfig()

        # Convert dict to FameNodeConfig if needed
        if isinstance(cfg, dict):
            cfg = FameNodeConfig(**cfg)

        opts = await make_common_opts(cfg)
        return FameNode(**opts)
