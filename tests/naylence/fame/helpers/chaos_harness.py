import asyncio
import random
from contextlib import asynccontextmanager
from typing import Callable

from naylence.fame.core import FameEnvelope
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric

DelayStrategy = Callable[[float], float]  # incoming delay → mutated delay
DropStrategy = Callable[[bytes], bool]  # frame bytes → should_drop?
DupStrategy = Callable[[bytes], int]  # frame bytes → how many duplicates?


def default_delay(d: float) -> float:
    return d + random.uniform(0, d * 3)  # up to 4× slower


def default_drop(_: bytes) -> bool:
    return random.random() < 0.02  # 2 % packet loss


def default_dup(_: bytes) -> int:
    return 1 + (random.random() < 0.02)  # 2 % duplicates


@asynccontextmanager
async def inject_chaos(
    fabric: "InProcessFameFabric",
    *,
    delay: DelayStrategy = default_delay,
    drop: DropStrategy = default_drop,
    dup: DupStrategy = default_dup,
):
    """
    Monkey-patch     fame.send(envelope) → chaos_send(envelope)
    for the lifetime of the context manager.
    Works for every service/node because they all share the same fabric.send().
    """
    orig_send = fabric.send

    async def chaos_send(envp: "FameEnvelope") -> None:
        raw = envp.model_dump_json().encode()

        # decide to drop?
        if drop(raw):
            return

        # maybe duplicate
        n = dup(raw)
        for _ in range(n):
            # maybe delay
            await asyncio.sleep(delay(0.001))
            await orig_send(envp)

    fabric.send = chaos_send  # type: ignore[attr-defined]
    try:
        yield
    finally:
        fabric.send = orig_send
