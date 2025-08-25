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

from naylence.fame.core import NodeHelloFrame, ResourceConfig, ResourceFactory


class PlacementDecision(BaseModel):
    accept: bool
    target_system_id: str
    assigned_path: str
    parent_physical_path: str
    accepted_logicals: Optional[Sequence[str]] = Field(default=None)
    rejected_logicals: Optional[Sequence[str]] = Field(default=None)
    metadata: Optional[Mapping[str, Any]] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None)
    reason: Optional[str] = Field(default=None)


@runtime_checkable
class FameNodePlacementStrategy(Protocol):
    """Pure function: figure out *where* the node should live."""

    async def place(self, hello_frame: NodeHelloFrame) -> PlacementDecision: ...


class NodePlacementConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "NodePlacementStrategy"


C = TypeVar("C", bound=NodePlacementConfig)


class NodePlacementStrategyFactory(ResourceFactory[FameNodePlacementStrategy, C]): ...
