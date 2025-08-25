import asyncio
import os

import pytest

from naylence.fame.channel.flow_controller import FlowController
from naylence.fame.core.protocol.envelope import create_fame_envelope
from naylence.fame.core.protocol.flow import FlowFlags
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.core.util.id_generator import generate_id
from naylence.fame.node import NodeLikeFactory
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.sentinel.sentinel_factory import SentinelConfig
from naylence.fame.util import logging
from tests.naylence.fame.helpers.loopback import LoopbackConnector, _linked_queues

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s\n")

logging.getLogger("naylence").setLevel(logging.TRACE)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)


@pytest.mark.asyncio
async def test_initial_credits_get_credits():
    fc = FlowController(initial_window=5)
    # get_credits should initialize to initial_window
    credits = fc.get_credits("test_flow_id")
    assert credits == 5


def test_add_credits_capping():
    fc = FlowController(initial_window=3)
    # initial credits at creation
    assert fc.get_credits("f1") == 3
    # consume some credits
    remaining = fc.consume("f1", credits=2)
    assert remaining == 1
    # refill beyond cap should cap at initial_window
    updated = fc.add_credits("f1", delta=10)
    assert updated == 3
    assert fc.get_credits("f1") == 3


def test_needs_refill():
    # low_watermark at 50% of initial_window = 2
    fc = FlowController(initial_window=4, low_watermark_ratio=0.5)
    # fresh flow has credits above watermark
    assert not fc.needs_refill("f2")
    # consume to below watermark
    remaining = fc.consume("f2", credits=3)
    assert remaining == 1
    assert fc.needs_refill("f2")


def test_add_negative_delta():
    fc = FlowController(initial_window=3)
    # initial credits
    assert fc.get_credits("neg") == 3
    # apply negative delta
    result = fc.add_credits("neg", delta=-5)
    # negative delta should not raise and result is an int ≤ initial_window
    assert isinstance(result, int)
    assert result <= 3


def test_next_window_sequence_and_flags():
    fc = FlowController(initial_window=5)
    # first envelope should be window_id=0 with SYN
    wid, flags = fc.next_window("f3")
    assert wid == 0
    assert flags & FlowFlags.SYN
    # second envelope should increment without SYN
    wid2, flags2 = fc.next_window("f3")
    assert wid2 == 1
    assert flags2 == FlowFlags.NONE
    # distinct flows track separately
    wid_other, other_flags = fc.next_window("other")
    assert wid_other == 0
    assert other_flags & FlowFlags.SYN


@pytest.mark.asyncio
async def test_reset_flow_and_sequence():
    fc = FlowController(initial_window=2)
    # advance sequence
    fc.next_window("f4")
    fc.next_window("f4")
    wid, _ = fc.next_window("f4")
    assert wid == 2
    # reset flow should clear sequence and credits
    fc.reset_flow("f4")
    # credits reset to initial
    assert fc.get_credits("f4") == 2
    # next window again emits SYN
    wid2, flags = fc.next_window("f4")
    assert wid2 == 0
    assert flags & FlowFlags.SYN


@pytest.mark.asyncio
async def test_acquire_blocks_and_unblocks():
    fc = FlowController(initial_window=1)
    # first acquire consumes the only credit
    await fc.acquire("f5")
    # second acquire should block until credit is added
    task = asyncio.create_task(fc.acquire("f5"))
    await asyncio.sleep(0.1)
    assert not task.done(), "acquire should block when credits exhausted"
    # refill one credit
    fc.add_credits("f5", delta=1)
    # now the task should complete without error
    await asyncio.wait_for(task, timeout=0.5)
    # after consume, credits go to zero again
    assert fc.get_credits("f5") == 0


@pytest.mark.asyncio
async def test_concurrent_acquire_allows_two_and_blocks_third():
    fc = FlowController(initial_window=2)
    # first two acquires proceed
    task1 = asyncio.create_task(fc.acquire("flow"))
    task2 = asyncio.create_task(fc.acquire("flow"))
    await asyncio.sleep(0.1)
    assert task1.done() and task2.done()
    # third acquire should block
    task3 = asyncio.create_task(fc.acquire("flow"))
    await asyncio.sleep(0.1)
    assert not task3.done(), "third acquire should block when credits exhausted"
    # refill one credit
    fc.add_credits("flow", delta=1)
    # now third task completes
    await asyncio.wait_for(task3, timeout=0.5)


@pytest.mark.asyncio
async def test_consume_not_negative():
    fc = FlowController(initial_window=2)
    # consuming more credits than available clamps to zero
    remaining = fc.consume("negflow", credits=5)
    assert remaining == 0
    assert fc.get_credits("negflow") == 0


@pytest.mark.asyncio
async def test_reset_flow_unblocks_acquire():
    fc = FlowController(initial_window=1)
    # consume initial credit
    await fc.acquire("resetflow")
    # next acquire blocks
    task = asyncio.create_task(fc.acquire("resetflow"))
    await asyncio.sleep(0.1)
    assert not task.done(), "acquire should block when credits exhausted"
    # reset the flow state, which should wake the waiter
    fc.reset_flow("resetflow")
    # ensure task completes
    await asyncio.wait_for(task, timeout=0.5)
    # after reset and acquire, credits should be initial_window - 1
    assert fc.get_credits("resetflow") == 0


@pytest.mark.asyncio
async def test_credit_round_trip():
    # enable flow-control
    os.environ["FAME_FLOW_CONTROL"] = "1"
    print()

    # make two in‐process routing nodes
    cfg_a = SentinelConfig.model_validate(
        {
            "mode": "dev",
            "requested_logicals": [],
            "is_router": True,
        },
        by_alias=True,
    )
    nodeA: Sentinel = await NodeLikeFactory.create_node(cfg_a)  # type: ignore
    nodeA._id = generate_id()
    await nodeA.start()

    cfg_b = SentinelConfig.model_validate(
        {
            "mode": "dev",
            "requested_logicals": [],
            "is_router": True,
        },
        by_alias=True,
    )
    nodeB: Sentinel = await NodeLikeFactory.create_node(cfg_b)  # type: ignore
    nodeB._id = generate_id()
    await nodeB.start()

    initial_window = 2  # 32

    # wire them together with a loopback connector pair
    # connAB, connBA = loopback_pair(initial_window=initial_window)

    (out1, in1), (out2, in2) = _linked_queues()
    connAB = LoopbackConnector("A->B", out1, in1, initial_window=initial_window)
    connBA = LoopbackConnector("B->A", out2, in2, initial_window=initial_window)

    await connAB.start(lambda env, ctx=None: nodeB.deliver(env, ctx))

    async def slow_handler(env, ctx=None):
        # simulate slow processing (e.g. disk write, DB call, etc.)
        await asyncio.sleep(0.5)
        # you could also forward to the router if you like:
        # await nodeA.deliver(env, ctx)

    await connBA.start(slow_handler)

    # register routes so each router knows how to reach the other
    await nodeA._route_manager.register_downstream_route("B", connAB)
    await nodeB._route_manager.register_downstream_route("A", connBA)

    # prepare 3× the initial‐window of envelopes

    envelopes = [
        create_fame_envelope(frame=DataFrame(payload=f"msg{i}"))  # type: ignore
        for i in range(initial_window * 3)
    ]

    # fire off a producer that will eventually hit back‐pressure
    async def producer():
        for env in envelopes:
            await connAB.send(env)

    print(f"\nTotal messages sent: {len(envelopes)}")
    prod_task = asyncio.create_task(producer())

    # give it a moment to send the first `initial_window` messages and then block
    await asyncio.sleep(0.1)
    print("Ensuring the producer is blocked by flow-control")
    assert not prod_task.done(), "Producer should be blocked by flow-control"

    print("Wait *longer* than the handler delay so B can catch up and ACK")
    # 5) Wait *longer* than the handler delay so B can catch up and ACK
    await asyncio.sleep(0.6)

    # after credit updates make it back to A, the producer unblocks and completes
    print("Waiting for the producer to unblock and complete")
    await prod_task

    # cleanly shut everything down
    print("Stopping node A")
    await nodeA.stop()
    print("Stopping node B")
    await nodeB.stop()
    print("Stopping connector AB")
    await connAB.stop()
    print("Stopping connector BA")
    await connBA.stop()


# 1) __init__ should reject non‐positive windows
def test_init_zero_window_raises():
    with pytest.raises(ValueError, match="initial_window must be > 0"):
        FlowController(0)  # :contentReference[oaicite:0]{index=0}


def test_init_negative_window_raises():
    with pytest.raises(ValueError):
        FlowController(-5)  # :contentReference[oaicite:1]{index=1}


# 2) Default low_watermark (25%) should trigger exactly at threshold
def test_default_low_watermark_triggers_at_threshold():
    # initial_window=8 → low_watermark=int(8*0.25)=2
    fc = FlowController(initial_window=8)
    # consume 6 → credits == 2
    rem = fc.consume("flowA", credits=6)
    assert rem == 2
    # now we should be at or below watermark
    assert fc.needs_refill("flowA")


# 3) Negative delta can push balance below zero
def test_add_negative_delta_pushes_below_zero():
    fc = FlowController(initial_window=3)
    # starting at 3, subtract 5 → clamps to 0
    new_bal = fc.add_credits("flowB", delta=-5)
    assert new_bal == 0
    assert fc.get_credits("flowB") == 0


# 4) Multiple flows track independently
def test_independent_flows_do_not_interfere():
    fc = FlowController(initial_window=5)
    fc.consume("A", credits=1)
    fc.consume("B", credits=2)
    assert fc.get_credits("A") == 4
    assert fc.get_credits("B") == 3


# 5) Even if balance is negative, acquire blocks until add_credits brings ≥1
@pytest.mark.asyncio
async def test_acquire_blocks_when_balance_negative():
    fc = FlowController(initial_window=2)
    # drive balance “negative” → clamps to 0
    fc.add_credits("negFlow", delta=-3)
    assert fc.get_credits("negFlow") == 0

    # now an acquire must block
    task = asyncio.create_task(fc.acquire("negFlow"))
    await asyncio.sleep(0.05)
    assert not task.done()
    # add enough to bring it back to 1
    fc.add_credits("negFlow", delta=5)
    # should unblock
    await asyncio.wait_for(task, timeout=0.2)
    assert fc.get_credits("negFlow") >= 0
