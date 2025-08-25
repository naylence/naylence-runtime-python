from typing import Any, Callable, Optional

from .node_placement_strategy import (
    NodePlacementConfig,
    NodePlacementStrategyFactory,
)
from .websocket_node_placement_strategy import WebSocketPlacementStrategy


class WebSocketFameNodePlacementConfig(NodePlacementConfig):
    type: str = "WebSocketNodePlacementStrategy"
    url: str


class WebSocketPlacementStrategyFactory(NodePlacementStrategyFactory):
    def __init__(
        self,
        parent_system_id_fn: Optional[Callable[[], str]] = None,
        parent_path_fn: Optional[Callable[[], str]] = None,
    ) -> None:
        super().__init__()
        self._parent_system_id_fn = parent_system_id_fn
        self._parent_path_fn = parent_path_fn

    async def create(
        self,
        config: Optional[WebSocketFameNodePlacementConfig] = None,
        **kwargs: dict[str, Any],
    ) -> WebSocketPlacementStrategy:
        assert config
        from naylence.fame.node.node import get_node

        return WebSocketPlacementStrategy(
            parent_ws_url=config.url,
            parent_system_id_fn=self._parent_system_id_fn or (lambda: get_node().id),
            parent_path_fn=self._parent_path_fn or (lambda: get_node().physical_path),
        )
