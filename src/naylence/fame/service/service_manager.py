from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Mapping, Optional, Protocol

from naylence.fame.core import FameAddress, FameService


class ServiceManager(ABC):
    @abstractmethod
    async def start(self): ...

    @abstractmethod
    async def stop(self): ...

    @abstractmethod
    async def register_service(self, service_name: str, service: FameService) -> FameAddress: ...

    @abstractmethod
    def get_local_services(self) -> Mapping[FameAddress, FameService]: ...

    @abstractmethod
    def resolve_by_capability(self, capability: object) -> FameService: ...

    @abstractmethod
    async def resolve_address_by_capability(self, capabilities: List[str]) -> Optional[FameAddress]: ...


class ServiceManagerProvider(Protocol):
    def get_service_manager(self) -> ServiceManager: ...
