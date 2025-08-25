"""
Chaos test ③ - “lossy link”

Guarantee under test
--------------------
* **At-most-once, in-order.**
  The fabric must not create duplicates; messages may be lost but the loss
  rate must stay within the chaos harness's configured drop-rate.
  Ordering must remain monotonic non-decreasing.

Chaos profile
-------------
* Delay: 0-5 ms extra latency per hop        (default_delay)
* Drop : 1 %                                 (drop_one_percent)
* Dup  : 0                                   (no_dup)

The size is larger than the two smoke tests but still finishes in < 1 s on
a typical CI runner.
"""

import asyncio
import random

import hypothesis.strategies as st
import pytest
from hypothesis import HealthCheck, given, settings

from naylence.fame.core import DataFrame, create_fame_envelope, format_address
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.service.in_memory_sink_service import InMemorySinkService
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory
from tests.naylence.fame.helpers.chaos_harness import default_delay, inject_chaos

# ────────── parameters ──────────
MAX_MESSAGES = 128
MAX_SUBSCRIBERS = 8
DROP_RATE = 0.01  # 1 % allowable loss
PUBLISH_DELAY_S = 0


def drop_one_percent(_: bytes) -> bool:
    return random.random() < DROP_RATE


def no_dup(_: bytes) -> int:
    return 1


# ────────── helpers ──────────
def is_monotonic(payloads):
    seqs = [int(p.decode()[1:]) for p in payloads]
    return all(a < b for a, b in zip(seqs, seqs[1:]))


# ────────── fixture ──────────
async def make_fixture():
    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    
    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
    
    node = FameNode(
        env_context=None,
        requested_logicals=["chaos.domain"],
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )
    await node.start()

    fabric = InProcessFameFabric(node=node)
    sink_service = InMemorySinkService(binding_manager=node.binding_manager, deliver=fabric.send)
    await fabric.serve(sink_service, "sink")

    sink_addr = format_address("chaos", "chaos.domain")
    sink = await fabric.create_sink(sink_addr)
    return node, fabric, sink


# ────────── property test ──────────
@given(
    n_msgs=st.integers(32, MAX_MESSAGES),  # avoid tiny edge-cases
    n_clients=st.integers(1, MAX_SUBSCRIBERS),
)
@settings(
    max_examples=20,
    suppress_health_check=[HealthCheck.data_too_large, HealthCheck.filter_too_much],
    deadline=None,
)
@pytest.mark.asyncio
async def test_lossy_link(n_msgs, n_clients):
    node, fabric, sink = await make_fixture()
    try:
        bufs = [[] for _ in range(n_clients)]

        # subscribers
        for idx in range(n_clients):

            async def handler(payload, idx=idx):
                bufs[idx].append(payload)

            await fabric.subscribe(sink, handler)

        # publisher
        async def publisher():
            for i in range(n_msgs):
                await fabric.send(create_fame_envelope(frame=DataFrame(payload=f"#{i}".encode()), to=sink))
                await asyncio.sleep(PUBLISH_DELAY_S)

        async with inject_chaos(
            fabric,
            delay=default_delay,
            drop=drop_one_percent,
            dup=no_dup,
        ):
            await publisher()
            # Allow in-flight envelopes to drain
            await asyncio.sleep(0.05)

        expected = {f"#{i}" for i in range(n_msgs)}
        max_missing = int(n_msgs * DROP_RATE) + 1  # <= 1 % missing permitted

        for buf in bufs:
            payloads = [p.decode() for p in buf]

            # 1️⃣ no duplicates
            assert len(payloads) == len(set(payloads))

            # 2️⃣ bounded loss
            missing = expected - set(payloads)
            assert len(missing) <= max_missing

            # 3️⃣ monotonic order
            assert is_monotonic(buf)

    finally:
        await node.stop()
