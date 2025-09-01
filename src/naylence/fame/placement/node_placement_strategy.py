from __future__ import annotations

from datetime import datetime
from typing import (
    Any,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    TypeVar,
    runtime_checkable,
)

from pydantic import BaseModel, ConfigDict, Field

from naylence.fame.core import NodeHelloFrame
from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource, create_resource


class PlacementDecision(BaseModel):
    accept: bool
    target_system_id: Optional[str] = Field(default=None)  # Must be set to None for root nodes
    assigned_path: str
    target_physical_path: Optional[str] = Field(default=None)  # Must be set to None for root nodes
    accepted_logicals: Optional[Sequence[str]] = Field(default=None)
    rejected_logicals: Optional[Sequence[str]] = Field(default=None)
    metadata: Optional[Mapping[str, Any]] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)
    reason: Optional[str] = Field(default=None)


@runtime_checkable
class NodePlacementStrategy(Protocol):
    """Pure function: figure out *where* the node should live."""

    async def place(self, hello_frame: NodeHelloFrame) -> PlacementDecision: ...


class NodePlacementConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "NodePlacementStrategy"


C = TypeVar("C", bound=NodePlacementConfig)


class NodePlacementStrategyFactory(ResourceFactory[NodePlacementStrategy, C]):
    @classmethod
    async def create_node_placement_strategy(
        cls, config: Optional[C] = None, **kwargs
    ) -> NodePlacementStrategy:
        if config:
            placement_strategy = await create_resource(NodePlacementStrategyFactory, config, **kwargs)
            return placement_strategy

        placement_strategy = await create_default_resource(NodePlacementStrategyFactory, **kwargs)

        assert placement_strategy, "Failed to create default NodePlacementStrategy"

        return placement_strategy
