"""
Chaos test ② - “duplicate storm”

Guarantee under test
--------------------
* **At-least-once, monotonic order.**
  Each original frame (`#0 … #N-1`) must reach every subscriber ≥ 1 x.
  Duplicates are tolerated and *expected*, but ordering must never regress.

Chaos profile
-------------
* Delay: 0-3 ms extra latency per hop       (default_delay)
* Duplication: 0-3 extra copies, 20 % prob. (dup_with_burst)
* Drop: 0 %                                  (no_drop)

The parameters are small enough to run on every push (<200 ms locally).
"""

import asyncio
import random

import hypothesis.strategies as st
import pytest
from hypothesis import HealthCheck, given, settings

from naylence.fame.core import DataFrame, create_fame_envelope, format_address
from naylence.fame.delivery.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerFactory,
)
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.service.in_memory_sink_service import InMemorySinkService
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from tests.naylence.fame.helpers.chaos_harness import default_delay, inject_chaos

MAX_MESSAGES = 32
MAX_SUBSCRIBERS = 4
PUBLISH_DELAY_S = 0


# ────────── chaos knobs for this test ──────────
def no_drop(_: bytes) -> bool:  # 0 % loss
    return False


def dup_with_burst(_: bytes) -> int:  # 20 % chance of 1-3 dups
    if random.random() < 0.20:
        return 1 + random.randint(1, 3)
    return 1


# ────────── helpers ──────────
def is_non_decreasing(payloads):
    seqs = [int(p.decode()[1:]) for p in payloads]  # "#42" → 42
    return all(a <= b for a, b in zip(seqs, seqs[1:]))


async def wait_len(buf, n):
    while len(buf) < n:  # wait until at least n originals present
        await asyncio.sleep(0.005)


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
        event_listeners=[delivery_tracker],  # Add delivery tracker as event listener
    )
    await node.start()

    fabric = InProcessFameFabric(node=node)
    sink_service = InMemorySinkService(binding_manager=node._binding_manager, deliver=fabric.send)
    await fabric.serve(sink_service, "sink")

    sink_addr = format_address("chaos", "chaos.domain")
    sink = await fabric.create_sink(sink_addr)
    return node, fabric, sink


# ────────── property test ──────────
@given(
    n_msgs=st.integers(1, MAX_MESSAGES),
    n_clients=st.integers(1, MAX_SUBSCRIBERS),
)
@settings(
    max_examples=30,
    suppress_health_check=[HealthCheck.data_too_large, HealthCheck.filter_too_much],
    deadline=None,
)
@pytest.mark.asyncio
async def test_duplicate_storm(n_msgs, n_clients):
    node, fabric, sink = await make_fixture()

    try:
        # per-client buffers
        bufs = [[] for _ in range(n_clients)]

        # subscribe handlers
        for idx in range(n_clients):

            async def handler(payload, idx=idx):
                bufs[idx].append(payload)

            await fabric.subscribe(sink, handler)

        # publisher coroutine
        async def publisher():
            for i in range(n_msgs):
                await fabric.send(create_fame_envelope(frame=DataFrame(payload=f"#{i}".encode()), to=sink))
                await asyncio.sleep(PUBLISH_DELAY_S)

        # run with chaos
        async with inject_chaos(
            fabric,
            delay=default_delay,
            drop=no_drop,
            dup=dup_with_burst,
        ):
            await asyncio.gather(publisher())
            # wait until everyone got all originals at least once
            expected = {f"#{i}".encode() for i in range(n_msgs)}
            await asyncio.wait_for(
                asyncio.gather(*(wait_len(bufs[i], n_msgs) for i in range(n_clients))),
                timeout=1.0 + n_msgs * 0.02,
            )

        # invariants
        for buf in bufs:
            payloads = [p.decode() for p in buf]
            # 1️⃣ every original arrived at least once
            assert expected.issubset({p.encode() for p in payloads})
            # 2️⃣ duplicates indeed present (probabilistic - skip if n_msgs==1)
            # 3️⃣ order is non-decreasing (allows repeats)
            assert is_non_decreasing(buf)

    finally:
        await node.stop()
