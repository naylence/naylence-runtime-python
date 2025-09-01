from __future__ import annotations

from pathlib import PurePosixPath

from naylence.fame.core import NodeHelloFrame

from .node_placement_strategy import (
    NodePlacementStrategy,
    PlacementDecision,
)


class StaticNodePlacementStrategy(NodePlacementStrategy):
    """
    Deterministic placement onto a predefined parent node and path.

    This strategy is transport-agnostic and intentionally simple: both
    target_system_id and target_physical_path are fixed values, provided
    via configuration upfront.
    """

    def __init__(self, *, target_system_id: str, target_physical_path: str) -> None:
        self._target_system_id = target_system_id
        self._target_physical_path = target_physical_path

    async def place(self, hello_frame: NodeHelloFrame) -> PlacementDecision:
        if hello_frame.system_id == self._target_system_id:
            # If the node id is the same as the target system id, it's a root node
            target_system_id = None
            target_physical_path = None
            assigned_path = f"/{hello_frame.system_id}"
        else:
            target_system_id = self._target_system_id
            target_physical_path = self._target_physical_path
            assigned_path = str(PurePosixPath(target_physical_path) / hello_frame.system_id)

        return PlacementDecision(
            accept=True,
            target_system_id=target_system_id,
            target_physical_path=target_physical_path,
            assigned_path=assigned_path,
            metadata={
                "accepted_logicals": hello_frame.logicals,
                "accepted_capabilities": hello_frame.capabilities,
            },
        )
