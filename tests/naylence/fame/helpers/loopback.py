import asyncio
import json

from naylence.fame.connector.base_async_connector import BaseAsyncConnector
from naylence.fame.errors.errors import FameTransportClose


def _linked_queues():
    q1, q2 = asyncio.Queue(), asyncio.Queue()
    return (q1, q2), (q2, q1)


class LoopbackConnector(BaseAsyncConnector):
    def __init__(self, name, out_q, in_q, *, no_recv: bool = False, initial_window: int = 32):
        super().__init__(drain_timeout=0, initial_window=initial_window)
        self.name = name
        self._out_q, self._in_q = out_q, in_q
        self._no_recv = no_recv

    async def start(self, inbound_handler):
        self._handler = inbound_handler
        self._send_task = asyncio.create_task(self._send_loop(), name="send-loop")
        if not self._no_recv:
            self._recv_task = asyncio.create_task(self._receive_loop(), name="receive-loop")

    async def _transport_send_bytes(self, data: bytes):
        # forward all frames (data *and* credit‐updates) to the peer
        print(f"Connector {self} sent message: {data}")
        await self._out_q.put(data)

    async def _transport_receive(self) -> bytes:
        msg = await self._in_q.get()
        if msg == {"__close__": True}:  # same sentinel
            raise FameTransportClose(1000, "loopback closed")
        if isinstance(msg, dict):  # legacy path
            msg = json.dumps(msg, separators=(",", ":")).encode("utf-8")
        print(f"{self} « {len(msg)} B")
        return msg

    async def _transport_close(self, code: int, reason: str):
        # signal peer to stop waiting
        await self._out_q.put({"__close__": True})

    def __repr__(self):
        return f"[{self.name}]"
