import asyncio
import time
from functools import partial

import pytest

from naylence.fame.core import DataFrame, create_fame_envelope, format_address
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.service.in_memory_sink_service import InMemorySinkService
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.tracking.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerFactory,
)

NUM_MESSAGES = 1000
NUM_SUBSCRIBERS = 100


@pytest.mark.asyncio
async def test_fame_stress_with_timing():
    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        env_context=None,
        requested_logicals=["stress.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    await node.start()

    fame = InProcessFameFabric(node=node)
    sink_service = InMemorySinkService(binding_manager=node.binding_manager, deliver=fame.send)
    await fame.serve(sink_service, "sink")

    fame_address = format_address("stress-test", "stress.domain")
    sink = await fame.create_sink(fame_address)

    # Each subscriber will collect their own received messages
    results = {i: [] for i in range(NUM_SUBSCRIBERS)}

    async def subscriber_handler(i, message):
        results[i].append(message)

    # Subscribe many subscribers
    subscribers = []
    for i in range(NUM_SUBSCRIBERS):
        sub_address = await fame.subscribe(fame_address, partial(subscriber_handler, i))
        subscribers.append(sub_address)

    # start the clock
    start_time = time.perf_counter()

    # Send messages
    for i in range(NUM_MESSAGES):
        env = create_fame_envelope(to=sink, frame=DataFrame(payload=f"data-{i}"))
        await fame.send(env)

    # Wait until *all* subscribers have seen all messages
    # (or timeout after, say, 60s to avoid a hung test)
    deadline = time.perf_counter() + 60.0
    while any(len(msgs) < NUM_MESSAGES for msgs in results.values()):
        if time.perf_counter() > deadline:
            pytest.fail("Timed out waiting for all messages to be delivered")
        await asyncio.sleep(0.01)

    # stop the clock
    elapsed = time.perf_counter() - start_time
    print(
        f"\n✅ Fame stress test completed: {NUM_MESSAGES} msgs × {NUM_SUBSCRIBERS} subs in {elapsed:.2f}s"
    )

    # Verify counts
    for sub_index, msgs in results.items():
        assert len(msgs) == NUM_MESSAGES, f"Subscriber {sub_index} missed messages!"

    await sink_service._stop_sink_service()
    await node.stop()
