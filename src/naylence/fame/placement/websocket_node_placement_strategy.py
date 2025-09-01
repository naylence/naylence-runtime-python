from __future__ import annotations

from pathlib import PurePosixPath
from typing import Callable

from naylence.fame.core import NodeHelloFrame

from .node_placement_strategy import (
    NodePlacementStrategy,
    PlacementDecision,
)


class WebSocketPlacementStrategy(NodePlacementStrategy):
    """
    Deprecated: use StaticNodePlacementStrategy instead.

    Legacy strategy that assigns nodes under a fixed parent. Historically tied to
    WebSocket but effectively transport-agnostic. Kept for backward compatibility
    while configs migrate.
    """

    def __init__(
        self,
        *,
        parent_system_id_fn: Callable[[], str],
        parent_path_fn: Callable[[], str],
    ):
        self._system_id_fn = parent_system_id_fn
        self._parent_path_fn = parent_path_fn

    async def place(self, hello_frame: NodeHelloFrame) -> PlacementDecision:
        parent_physical_path = self._parent_path_fn()
        assigned_path = str(PurePosixPath(parent_physical_path) / hello_frame.system_id)

        target_system_id = self._system_id_fn()
        return PlacementDecision(
            accept=True,
            target_system_id=target_system_id,
            target_physical_path=parent_physical_path,
            assigned_path=assigned_path,
            metadata={
                "accepted_logicals": hello_frame.logicals,
                "accepted_capabilities": hello_frame.capabilities,
            },
        )
