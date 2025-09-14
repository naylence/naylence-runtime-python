from __future__ import annotations

import importlib.metadata
from typing import Any, AsyncIterator, Dict, Mapping, Optional, cast

from naylence.fame.config.config import ExtendedFameConfig
from naylence.fame.core import (
    DEFAULT_INVOKE_TIMEOUT_MILLIS,
    SINK_CAPABILITY,
    DataFrame,
    DeliveryAckFrame,
    FameAddress,
    FameConfig,
    FameEnvelope,
    FameFabric,
    FameMessageHandler,
    FameService,
    FameServiceProxy,
    generate_id,
)
from naylence.fame.node.node_like import NodeLike
from naylence.fame.node.node_like_factory import NodeLikeFactory
from naylence.fame.service.service_manager import ServiceManager
from naylence.fame.service.sink_service import SinkService
from naylence.fame.util.logging import getLogger
from naylence.fame.util.util import decode_fame_data_payload

logger = getLogger(__name__)


class InProcessFameFabric(FameFabric):
    def __init__(
        self,
        node: Optional[NodeLike] = None,
        config: Optional[FameConfig | dict] = None,
        capabilities: Optional[Dict[object, str]] = None,
    ):
        super().__init__()

        self._current_node: NodeLike = node  # type: ignore
        self._is_managed_node = bool(node)
        if config:
            self._config = (
                config
                if isinstance(config, ExtendedFameConfig)
                else ExtendedFameConfig.model_validate(config, by_alias=True)
            )
        else:
            self._config = None

    async def start(self):
        # Log package version at startup
        try:
            version = importlib.metadata.version("naylence-runtime")
            logger.info("naylence_runtime_startup", version=version, fabric_type="in_process")
        except importlib.metadata.PackageNotFoundError:
            logger.warning(
                "naylence_runtime_version_not_found",
                message="Could not determine package version",
                fabric_type="in_process",
            )

        logger.debug("starting_fabric", type="in_process")  # type: ignore
        if not self._current_node:
            self._current_node = await NodeLikeFactory.create_node(
                self._config.node if self._config else None
            )
            await self._current_node.__aenter__()
            self._is_managed_node = True

    async def stop(self):
        if self._is_managed_node and self._current_node:
            await self._current_node.__aexit__(None, None, None)

    @property
    def _service_manager(self) -> ServiceManager:
        return getattr(self._current_node, "_service_manager")

    @property
    def node(self) -> NodeLike:
        return self._current_node

    async def send(
        self, envelope: FameEnvelope, timeout_ms: Optional[int] = None
    ) -> Optional[DeliveryAckFrame]:
        """
        Send an envelope through the fabric.

        Encryption and signing decisions are now handled by the node's SecurityPolicy.

        Args:
            envelope: The envelope to send
        """
        return await self._current_node.send(envelope, timeout_ms=timeout_ms)

    async def invoke(
        self,
        address: FameAddress,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> Any:
        return await self._current_node.invoke(address, method, params, timeout_ms=timeout_ms)

    async def invoke_by_capability(
        self,
        capabilities: list[str],
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> Any:
        return await self._current_node.invoke_by_capability(
            capabilities, method, params, timeout_ms=timeout_ms
        )

    async def invoke_stream(
        self,
        address: FameAddress,
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> AsyncIterator[Any]:
        return await self._current_node.invoke_stream(address, method, params, timeout_ms=timeout_ms)

    async def serve(self, service: FameService, service_name: Optional[str] = None) -> FameAddress:
        service_name = service_name or getattr(service, "name", None)
        if not service_name:
            raise ValueError("service_name parameter not set and service doesn't define 'name' property")
        return await self._service_manager.register_service(service_name, service)

    async def invoke_by_capability_stream(
        self,
        capabilities: list[str],
        method: str,
        params: dict[str, Any],
        timeout_ms: int = DEFAULT_INVOKE_TIMEOUT_MILLIS,
    ) -> AsyncIterator[Any]:
        return await self._current_node.invoke_by_capability_stream(
            capabilities, method, params, timeout_ms=timeout_ms
        )

    def get_local_services(self) -> Mapping[FameAddress, FameService]:
        return self._service_manager.get_local_services()

    def resolve_service_by_capability(self, capability: str) -> FameService:
        return self._service_manager.resolve_by_capability(capability)

    @property
    def sink_service(self) -> SinkService:
        service = self.resolve_service_by_capability(SINK_CAPABILITY)
        if not isinstance(service, SinkService | FameServiceProxy):
            raise RuntimeError(f"Invalid service type. Expected: {SinkService}, actual: {type(service)}")
        return cast(SinkService, service)

    async def create_sink(self, name: Optional[str] = None) -> FameAddress:
        sink_name = name or f"sink-{generate_id()}"
        return await self.sink_service.create_sink({"name": sink_name})

    async def subscribe(
        self,
        sink_address: FameAddress,
        handler: FameMessageHandler,
        name: Optional[str] = None,
    ) -> None:
        subscriber_name = name or f"sink-subscriber-{generate_id()}"

        async def _decode_and_handle(env: FameEnvelope, context: Optional[Any] = None) -> Optional[Any]:
            if not isinstance(env.frame, DataFrame):
                raise RuntimeError(
                    f"Invalid envelope frame type. Expected: {DataFrame}, actual: {type(env.frame)}"
                )

            result = await handler(decode_fame_data_payload(env.frame))

            # Check if result is a FameMessageResponse
            from naylence.fame.core import FameMessageResponse

            if isinstance(result, FameMessageResponse):
                # Handler provided a response envelope - return it so the listener can deliver it
                return result
            # Note: For message handlers, None result (no response) or Any result (ignored) are both valid
            return None

        subscriber_address = await self._current_node.listen(subscriber_name, _decode_and_handle)
        await self.sink_service.subscribe(
            {
                "sink_address": sink_address,
                "subscriber_address": subscriber_address,
            }
        )
