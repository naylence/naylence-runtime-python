from typing import Any, Callable, Optional

from .node_placement_strategy import (
    NodePlacementConfig,
    NodePlacementStrategyFactory,
)
from .websocket_node_placement_strategy import WebSocketPlacementStrategy


class WebSocketFameNodePlacementConfig(NodePlacementConfig):
    type: str = "WebSocketNodePlacementStrategy"
    # url: str


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
        config: Optional[WebSocketFameNodePlacementConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> WebSocketPlacementStrategy:
        assert config
        from naylence.fame.node.node import get_node

        if isinstance(config, dict):
            config = WebSocketFameNodePlacementConfig(**config)

        # Maintain legacy behavior for direct use, but encourage migration by emitting a warning
        import warnings

        warnings.warn(
            "WebSocketPlacementStrategyFactory is deprecated; use StaticNodePlacementStrategyFactory",
            DeprecationWarning,
        )

        # Delegate to static strategy with resolved current node values when callables not provided
        parent_system_id = (
            self._parent_system_id_fn() if self._parent_system_id_fn is not None else get_node().id
        )
        target_physical_path = (
            self._parent_path_fn() if self._parent_path_fn is not None else get_node().physical_path
        )

        # # Create a StaticNodePlacementStrategy instance to perform placement
        # _ = StaticNodePlacementStrategy(
        #     target_system_id=parent_system_id, target_physical_path=target_physical_path
        # )

        # For compatibility, still return a WebSocketPlacementStrategy instance wired with fixed values
        return WebSocketPlacementStrategy(
            parent_system_id_fn=lambda: parent_system_id,
            parent_path_fn=lambda: target_physical_path,
        )
