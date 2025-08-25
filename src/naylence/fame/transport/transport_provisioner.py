from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Optional,
    Protocol,
    TypeVar,
    runtime_checkable,
)

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.core import NodeHelloFrame, ResourceConfig, ResourceFactory

if TYPE_CHECKING:
    from naylence.fame.placement.node_placement_strategy import PlacementDecision


class TransportProvisionResult(BaseModel):
    directive: dict[str, Any]
    cleanup_handle: Optional[str] = Field(default=None)
    metadata: Optional[Dict] = Field(default=None)

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )


@runtime_checkable
class TransportProvisioner(Protocol):
    """
    Side-effectful: allocate Redis streams, Kafka topics, etc.
    """

    async def provision(
        self,
        decision: PlacementDecision,
        hello: NodeHelloFrame,
        full_metadata: Dict,
        attach_token: Optional[str] = None,
    ) -> TransportProvisionResult: ...

    async def deprovision(self, cleanup_handle: str) -> None: ...


class TransportProvisionerConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "TransportProvisioner"


C = TypeVar("C", bound=TransportProvisionerConfig)


class TransportProvisionerFactory(ResourceFactory[TransportProvisioner, C]): ...
