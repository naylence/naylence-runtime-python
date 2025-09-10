import asyncio

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

# ─────────────────────────────  tier parameters  ───────────────────────────── #

MAX_MESSAGES = 32  # ▲ smoke-tier size: fast but non-trivial
MAX_SUBSCRIBERS = 4
PUBLISH_DELAY_S = 0  # keep publisher hot; chaos adds its own jitter


# No loss, no duplications for the smoke tier
def no_drop(_: bytes) -> bool:
    return False


def no_dup(_: bytes) -> int:
    return 1


# ──────────────────────────────  fixtures  ─────────────────────────────────── #


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
    sink_service = InMemorySinkService(
        binding_manager=node.binding_manager,
        deliver=fabric.send,
    )
    await fabric.serve(sink_service, "sink")

    addr = format_address("chaos", "chaos.domain")
    sink = await fabric.create_sink(addr)
    return node, fabric, sink, sink_service


# ───────────────────────────────  helpers  ─────────────────────────────────── #


def is_monotonic(payloads):
    """Check strict increasing order of '#42' → 42 integers."""
    seqs = [int(p.decode()[1:]) for p in payloads]
    return all(a < b for a, b in zip(seqs, seqs[1:]))


async def _wait_for_length(buf, length, interval=0.005):
    while len(buf) < length:
        await asyncio.sleep(interval)


# ───────────────────────────────  property  ────────────────────────────────── #


@given(
    n_msgs=st.integers(1, MAX_MESSAGES),
    n_clients=st.integers(1, MAX_SUBSCRIBERS),
)
@settings(
    max_examples=30,  # ▲ fewer but quicker
    suppress_health_check=[HealthCheck.data_too_large, HealthCheck.filter_too_much],
    deadline=None,
)
@pytest.mark.asyncio
async def test_end_to_end_under_chaos(n_msgs, n_clients):
    node, fabric, sink, sink_service = await make_fixture()

    try:
        # 1️⃣ per-client buffers
        results = [[] for _ in range(n_clients)]

        # 2️⃣ subscribe handlers
        for idx in range(n_clients):

            async def handler(payload, idx=idx):
                results[idx].append(payload)

            await fabric.subscribe(sink, handler)

        # 3️⃣ publisher task
        async def publisher():
            for i in range(n_msgs):
                await fabric.send(create_fame_envelope(frame=DataFrame(payload=f"#{i}".encode()), to=sink))
                await asyncio.sleep(PUBLISH_DELAY_S)

        # 4️⃣ run with chaos (no loss / dup, only jitter)
        async with inject_chaos(
            fabric,
            delay=default_delay,
            drop=no_drop,  # ▲
            dup=no_dup,  # ▲
        ):
            await asyncio.gather(publisher())
            timeout = 1.0 + n_msgs * 0.02  # ▲ elastic timeout
            await asyncio.wait_for(
                asyncio.gather(*[_wait_for_length(buf, n_msgs) for buf in results]),
                timeout=timeout,
            )

        # 5️⃣ invariants – at-least-once, in-order, no duplicates
        expected = {f"#{i}" for i in range(n_msgs)}
        for buf in results:
            payloads = [p.decode() for p in buf]
            assert set(payloads) == expected  # no loss, no extras
            assert is_monotonic(buf)  # in order
            assert len(buf) == len(set(buf))  # no dups

    finally:
        await node.stop()
