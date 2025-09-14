from __future__ import annotations

from typing import Any, Dict, List, Optional

from naylence.fame.channel.in_memory.in_memory_fanout_broker import InMemoryFanoutBroker
from naylence.fame.core import (
    FameAddress,
    FameFabric,
    FameService,
    FameServiceFactory,
    ReadWriteChannel,
    SenderProtocol,
    Subscription,
    WriteChannel,
    extract_envelope_and_context,
    generate_id,
    make_fame_address,
)
from naylence.fame.node.binding_manager import BindingManager
from naylence.fame.node.node import get_node
from naylence.fame.service.sink_service import (
    CreateSinkParams,
    SinkService,
    SubscribeParams,
)
from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class FameFabricWriteChannel(WriteChannel):
    """A write-only channel that sends messages to a target node address."""

    def __init__(self, deliver: SenderProtocol, destination: FameAddress):
        self._deliver = deliver
        self._destination = destination

    async def send(self, message) -> None:
        # Handle both FameEnvelope and FameChannelMessage

        envelope, context = extract_envelope_and_context(message)

        if envelope is None:
            return

        copy = envelope.model_copy()
        copy.to = self._destination

        # Use the deliver method with context if available
        # Check if the deliver callable is a bound method that supports context
        if context is not None:
            try:
                # Try to get the underlying object if it's a bound method
                deliver_obj = getattr(self._deliver, "__self__", None)
                if deliver_obj and hasattr(deliver_obj, "deliver"):
                    await deliver_obj.deliver(copy, context)  # type: ignore
                    return
            except (AttributeError, TypeError):
                pass

        # Fallback to regular delivery without context
        return await self._deliver(copy)

    async def close(self) -> None:
        pass


class InMemorySinkService(SinkService):
    def __init__(
        self,
        *,
        binding_manager: Optional[BindingManager] = None,
        deliver: Optional[SenderProtocol] = None,
        **kwargs,
    ):
        self._binding_manager = binding_manager or get_node().binding_manager
        self._deliver = deliver or FameFabric.current().send

        self._subscriptions: Dict[str, List[Subscription]] = {}
        self._sinks: Dict[FameAddress, ReadWriteChannel] = {}
        self._fanouts: Dict[str, InMemoryFanoutBroker] = {}
        self.name = "sink-service"

    async def stop(self) -> None:
        """Graceful shutdown so DefaultServiceManager.stop() can clean us up."""
        await self._stop_sink_service()

    async def handle_rpc_request(self, method: str, params: Dict) -> Any:
        if method in ["createSink", "create_sink", "sink/create"]:
            return await self.create_sink(params)  # type: ignore
        elif method == "subscribe":
            return await self.subscribe(params)  # type: ignore
        else:
            raise ValueError(f"Unknown RPC method: {method}")

    async def _stop_sink_service(self) -> None:
        for broker in self._fanouts.values():
            try:
                await broker.stop()
            except Exception as err:
                logger.error("failed_to_stop_sink_service", error=err, exc_info=True)
        self._fanouts.clear()
        self._sinks.clear()
        self._subscriptions.clear()

    async def create_sink(self, params: CreateSinkParams) -> FameAddress:
        logger.debug("creating_sink", sink_params=params)
        key = params["name"] or f"sink-{generate_id()}"

        binding = await self._binding_manager.bind(key)
        sink_address = binding.address

        broker = InMemoryFanoutBroker(binding.channel)
        self._sinks[sink_address] = binding.channel
        self._fanouts[sink_address] = broker

        await broker.start()

        logger.debug("created_sink", sink_params=params, sink_address=sink_address)

        return sink_address

    async def subscribe(self, params: SubscribeParams) -> None:
        logger.debug("subscribing_to_sink", sink_params=params)
        sink_address = params["sink_address"]
        subscriber_address = make_fame_address(params["subscriber_address"])

        broker = self._fanouts.get(sink_address)
        if not broker:
            raise ValueError(f"No sink found for {sink_address}")

        channel = FameFabricWriteChannel(self._deliver, subscriber_address)  # type: ignore

        broker.add_subscriber(channel)

        sub = Subscription(channel=channel, address=subscriber_address)
        self._subscriptions.setdefault(sink_address, []).append(sub)

        logger.debug("subscribed_to_sink", sink_params=params)

    async def unsubscribe(self, subscription: Subscription) -> None:
        key = subscription.address
        subs = self._subscriptions.get(key)
        if not subs:
            return

        try:
            subs.remove(subscription)
        except ValueError:
            return

        if not subs:
            self._subscriptions.pop(key)

        broker = self._fanouts.get(key)
        if broker:
            broker.remove_subscriber(subscription.channel)  # type: ignore


class InMemorySinkServiceFactory(FameServiceFactory):
    async def create(self, config: Optional[Any] = None, **kwargs: Any) -> FameService:
        return InMemorySinkService(**kwargs)
