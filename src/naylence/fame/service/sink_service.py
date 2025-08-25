from __future__ import annotations

from abc import abstractmethod
from typing import Any, List, TypedDict

from naylence.fame.core import SINK_CAPABILITY, FameAddress, FameRPCService


def is_sink_service(service: Any) -> bool:
    return bool(service and getattr(service, SINK_CAPABILITY, False))


class CreateSinkParams(TypedDict):
    name: str


class SubscribeParams(TypedDict):
    sink_address: str
    subscriber_address: str


class SinkService(FameRPCService):
    _capabilities = [SINK_CAPABILITY]

    @property
    def capabilities(self) -> List[str]:
        return SinkService._capabilities

    @abstractmethod
    async def create_sink(self, params: CreateSinkParams) -> FameAddress: ...

    @abstractmethod
    async def subscribe(self, params: SubscribeParams) -> None: ...
