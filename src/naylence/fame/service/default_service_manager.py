from __future__ import annotations

import asyncio
import inspect
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional

from naylence.fame.core import (
    DEFAULT_POLLING_TIMEOUT_MS,
    Addressable,
    FameAddress,
    FameMessageService,
    FameRPCService,
    FameService,
    FameServiceFactory,
    InvokeProtocol,
    ServeProtocol,
    ServeRPCProtocol,
)
from naylence.fame.factory import ExtensionManager, create_resource
from naylence.fame.service.service_manager import ServiceManager


class DefaultServiceManager(ServiceManager):
    def __init__(
        self,
        *,
        default_service_configs: Optional[List[Any]] = None,
        invoke: InvokeProtocol,
        serve_rpc: ServeRPCProtocol,
        serve: ServeProtocol,
        capability_map: Optional[Dict[object, FameAddress]] = None,
        poll_timeout_ms: Optional[int] = DEFAULT_POLLING_TIMEOUT_MS,
    ):
        self._invoke = invoke
        self._serve_rpc = serve_rpc
        self._serve = serve
        self._capability_map = capability_map or {}
        self._services: Dict[FameAddress, FameService] = {}
        self._poll_timeout_ms = poll_timeout_ms
        self._default_service_configs = default_service_configs or []
        self._started = False
        self._extension_manager: Optional[ExtensionManager] = None

    async def start(self):
        self._extension_manager = ExtensionManager.lazy_init(
            group="naylence.FameServiceFactory", base_type=FameServiceFactory
        )
        if self._started:
            return
        for service_config in self._default_service_configs:
            service_name = service_config.get("name", None)
            if service_name:
                service = await create_resource(FameServiceFactory, service_config)
                await self.register_service(service_name, service)
        self._started = True

    async def stop(self):
        """
        Shut down the service manager and *each* registered service
        that exposes a ``stop`` coroutine or function.

        The call is idempotent: repeated invocations after the first
        do nothing.
        """
        if not self._started:
            return

        async def _maybe_stop(service: FameService):
            stop_fn = getattr(service, "stop", None)
            if not callable(stop_fn):
                return

            if inspect.iscoroutinefunction(stop_fn):
                await stop_fn()
            else:
                # run sync stopper in the default executor so we
                # don’t block the event-loop if it does I/O
                await asyncio.to_thread(stop_fn)

        await asyncio.gather(*(_maybe_stop(s) for s in self._services.values()))
        self._started = False

    async def register_service(self, service_name: str, service: FameService) -> FameAddress:
        start_fn = getattr(service, "start", None)
        if callable(start_fn):
            if inspect.iscoroutinefunction(start_fn):
                await start_fn()
            else:
                # run sync stopper in the default executor so we
                # don’t block the event-loop if it does I/O
                await asyncio.to_thread(start_fn)

        if isinstance(service, FameMessageService):
            address = await self._serve(
                service_name,
                service.handle_message,
                capabilities=service.capabilities,
                poll_timeout_ms=self._poll_timeout_ms,
            )
        elif isinstance(service, FameRPCService):
            address = await self._serve_rpc(
                service_name,
                service.handle_rpc_request,
                capabilities=service.capabilities,
                poll_timeout_ms=self._poll_timeout_ms,
            )
        else:
            raise TypeError(f"{service!r} must implement FameService or FameRPCService")

        self._services[address] = service
        if isinstance(service, Addressable):
            service.address = address

        return address

    def get_local_services(self) -> Mapping[FameAddress, FameService]:
        return MappingProxyType(self._services)

    def resolve_by_capability(self, capability: object) -> FameService:
        for addr, svc in self.get_local_services().items():
            if capability in getattr(svc, "capabilities", set()):
                return FameService.remote_by_address(addr, invoke=self._invoke)

        if capability in self._capability_map:
            return FameService.remote_by_address(self._capability_map[capability], invoke=self._invoke)

        raise ValueError(f"Capability {capability} not available")

    async def resolve_address_by_capability(self, capabilities: List[str]) -> Optional[FameAddress]:
        """
        Find the address of the first local service that supports all listed capabilities.
        """

        for address, service in self.get_local_services().items():
            svc_caps = getattr(service, "capabilities", set())
            if all(cap in svc_caps for cap in capabilities):
                return address

        # fallback to static capability map (only if single-capability match is allowed)
        if len(capabilities) == 1:
            address = self._capability_map.get(capabilities[0])
            if address:
                return address

        return None
