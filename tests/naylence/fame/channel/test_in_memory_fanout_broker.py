import asyncio
from typing import Any, List

import pytest

from naylence.fame.channel.in_memory.in_memory_channel import InMemoryReadWriteChannel
from naylence.fame.channel.in_memory.in_memory_fanout_broker import InMemoryFanoutBroker
from naylence.fame.core import (
    DataFrame,
    create_channel_message,
    create_fame_envelope,
    local_delivery_context,
)


class _RecordingCloseableSubscriber:
    """Capture messages delivered by the broker and track close calls."""

    def __init__(self) -> None:
        self.messages: List[Any] = []
        self.closed = False
        self._received = asyncio.Event()

    async def send(self, message: Any) -> None:
        self.messages.append(message)
        self._received.set()

    async def close(self) -> None:
        self.closed = True

    async def wait_for_message(self, timeout: float = 0.2) -> None:
        await asyncio.wait_for(self._received.wait(), timeout)


class _CloseErrorSubscriber(_RecordingCloseableSubscriber):
    """Subscriber whose close method raises to test error handling."""

    def __init__(self) -> None:
        super().__init__()
        self.close_attempts = 0

    async def close(self) -> None:
        self.close_attempts += 1
        raise RuntimeError("close failed intentionally")


class _FailingSubscriber:
    """Subscriber that raises on send to exercise removal logic."""

    def __init__(self) -> None:
        self.attempts = 0

    async def send(self, message: Any) -> None:
        self.attempts += 1
        raise RuntimeError("intentional send failure")

    async def close(self) -> None:  # pragma: no cover - never called once removed
        pass


@pytest.mark.asyncio
async def test_fanout_broker_broadcasts_to_all_subscribers() -> None:
    sink = InMemoryReadWriteChannel()
    broker = InMemoryFanoutBroker(sink, _poll_timeout_ms=10)

    await broker.start()
    await broker.start()  # second call should be a no-op

    primary_sub = InMemoryReadWriteChannel()
    closable_sub = _RecordingCloseableSubscriber()
    erroring_sub = _CloseErrorSubscriber()
    broker.add_subscriber(primary_sub)
    broker.add_subscriber(closable_sub)
    broker.add_subscriber(erroring_sub)

    envelope = create_fame_envelope(frame=DataFrame(payload="hello"))

    await sink.send(envelope)
    await closable_sub.wait_for_message()
    await erroring_sub.wait_for_message()
    received = await asyncio.wait_for(primary_sub.receive(timeout=1000), timeout=0.5)

    assert received.id == envelope.id
    assert closable_sub.messages == [envelope]
    assert erroring_sub.messages == [envelope]

    # None payloads should be ignored by the fanout loop, covering guard clauses
    await sink.send(None)  # type: ignore[arg-type]

    await broker.stop()

    assert closable_sub.closed
    assert erroring_sub.close_attempts == 1
    assert len(broker._subscribers) == 0


@pytest.mark.asyncio
async def test_fanout_broker_removes_failing_subscriber_and_preserves_context() -> None:
    sink = InMemoryReadWriteChannel()
    broker = InMemoryFanoutBroker(sink, _poll_timeout_ms=10)

    await broker.start()

    healthy_sub = InMemoryReadWriteChannel()
    failing_sub = _FailingSubscriber()
    broker.add_subscriber(healthy_sub)
    broker.add_subscriber(failing_sub)

    envelope = create_fame_envelope(frame=DataFrame(payload="context"))
    context = local_delivery_context(system_id="router-A")
    message = create_channel_message(envelope, context=context)

    await sink.send(message)
    received = await asyncio.wait_for(healthy_sub.receive(timeout=1000), timeout=0.5)

    assert received == message

    # Allow loop to process removal of the failing subscriber
    deadline = asyncio.get_running_loop().time() + 0.5
    while failing_sub in broker._subscribers:
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("Failing subscriber was not removed")
        await asyncio.sleep(0.01)

    await broker.stop()


@pytest.mark.asyncio
async def test_fanout_broker_recovers_from_unexpected_message(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = InMemoryReadWriteChannel()
    broker = InMemoryFanoutBroker(sink, _poll_timeout_ms=5)

    await broker.start()

    original_sleep = asyncio.sleep
    sleep_calls: List[float] = []

    async def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)
        await original_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await sink.send(object())
    await original_sleep(0.05)

    assert any(abs(call - 0.5) < 0.05 for call in sleep_calls)

    await broker.stop()
