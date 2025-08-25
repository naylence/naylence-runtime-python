from __future__ import annotations

from naylence.fame.channel.in_memory.in_memory_channel import InMemoryReadWriteChannel
from naylence.fame.core import Binding, FameAddress


class InMemoryBinding(Binding):
    def __init__(self, address: FameAddress):
        self.address = address
        self.channel = InMemoryReadWriteChannel()
