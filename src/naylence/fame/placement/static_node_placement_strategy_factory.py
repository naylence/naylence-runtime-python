from __future__ import annotations

from typing import Any, Optional

from .node_placement_strategy import (
    NodePlacementConfig,
    NodePlacementStrategy,
    NodePlacementStrategyFactory,
)


class StaticNodePlacementConfig(NodePlacementConfig):
    type: str = "StaticNodePlacementStrategy"
    target_system_id: str
    target_physical_path: str


class StaticNodePlacementStrategyFactory(NodePlacementStrategyFactory):
    async def create(
        self,
        config: Optional[StaticNodePlacementConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> NodePlacementStrategy:
        assert config

        from .static_node_placement_strategy import StaticNodePlacementStrategy

        if isinstance(config, dict):
            # Support legacy alias if someone passes deprecated name
            if config.get("type") == "WebSocketNodePlacementStrategy":
                import warnings

                warnings.warn(
                    "WebSocketNodePlacementStrategy is deprecated; use StaticNodePlacementStrategy",
                    DeprecationWarning,
                )
                config = {**config, "type": "StaticNodePlacementStrategy"}

            config = StaticNodePlacementConfig(**config)

        return StaticNodePlacementStrategy(
            target_system_id=config.target_system_id,
            target_physical_path=config.target_physical_path,
        )
