import importlib
from typing import TYPE_CHECKING

from .router import RouterState, RoutingAction
from .routing_policy import RoutingPolicy

if TYPE_CHECKING:
    from .sentinel import Sentinel

__all__ = [
    "Sentinel",
    "RoutingPolicy",
    "RouterState",
    "RoutingAction",
]


def __getattr__(name: str):
    if name == "RoutingNode":
        return importlib.import_module(__name__ + ".routing_node").RoutingNode
    elif name == "Sentinel":
        return importlib.import_module(__name__ + ".sentinel").Sentinel
    raise AttributeError(f"module {__name__!r} has no attribute {name}")
