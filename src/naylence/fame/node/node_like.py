from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Optional,
    Protocol,
    runtime_checkable,
)

from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.node.admission.admission_client import AdmissionClient

if TYPE_CHECKING:
    from naylence.fame.node.node_event_listener import NodeEventListener
    from naylence.fame.security.security_manager import SecurityManager

from naylence.fame.core import (
    Binding,
    DeliveryAckFrame,
    EnvelopeFactory,
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    FameEnvelopeHandler,
    FameRPCHandler,
)


@runtime_checkable
class NodeLike(AbstractAsyncContextManager, Protocol):
    @property
    def id(self) -> str: ...

    @property
    def sid(self) -> Optional[str]: ...

    @property
    def physical_path(self) -> str: ...

    @property
    def accepted_logicals(self) -> set[str]: ...

    @property
    def envelope_factory(self) -> EnvelopeFactory: ...

    @property
    def delivery_policy(self) -> Optional[DeliveryPolicy]: ...

    @property
    def default_binding_path(self) -> str: ...

    @property
    def has_parent(self) -> bool: ...

    @property
    def security_manager(self) -> Optional[SecurityManager]: ...

    @property
    def admission_client(self) -> Optional[AdmissionClient]: ...

    @property
    def event_listeners(self) -> list[NodeEventListener]: ...

    def add_event_listener(self, listener: NodeEventListener) -> None: ...

    def remove_event_listener(self, listener: NodeEventListener) -> None: ...

    async def _dispatch_event(self, event_name: str, *args, **kwargs) -> None: ...

    async def _dispatch_envelope_event(
        self, event_name: str, *args, **kwargs
    ) -> Optional[FameEnvelope]: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def bind(self, participant: str) -> Binding: ...

    async def unbind(self, participant: str) -> None: ...

    async def send(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        delivery_policy: Optional[DeliveryPolicy] = None,
        delivery_fn: Optional[
            Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[Any]]
        ] = None,
        timeout_ms: Optional[int] = None,
    ) -> Optional[DeliveryAckFrame]: ...

    async def listen(
        self,
        recipient: str,
        handler: FameEnvelopeHandler,
        poll_timeout_ms: Optional[int] = None,
    ) -> FameAddress: ...

    async def listen_rpc(
        self,
        service_name: str,
        handler: FameRPCHandler,
        poll_timeout_ms: int,
    ) -> FameAddress: ...

    async def invoke(
        self,
        target_addr: FameAddress,
        method: str,
        params: dict[str, Any],
        timeout_ms: int,
    ) -> Any: ...

    async def invoke_by_capability(
        self,
        capabilities: list[str],
        method: str,
        params: dict[str, Any],
        timeout_ms: int,
    ) -> Any: ...

    async def invoke_stream(
        self,
        target_addr: FameAddress,
        method: str,
        params: dict[str, Any],
        timeout_ms: int,
    ) -> AsyncIterator[Any]: ...

    async def invoke_by_capability_stream(
        self,
        capabilities: list[str],
        method: str,
        params: dict[str, Any],
        timeout_ms: int,
    ) -> AsyncIterator[Any]: ...

    async def deliver(
        self,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> None: ...

    async def deliver_local(
        self,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> None: ...

    async def forward_upstream(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None: ...

    def has_local(self, address: FameAddress) -> bool: ...

    @property
    def upstream_connector(self) -> Optional[FameConnector]: ...

    @property
    def public_url(self) -> Optional[str]: ...

    @property
    def storage_provider(self) -> Any: ...

    def gather_supported_callback_grants(self) -> list[dict[str, Any]]: ...
