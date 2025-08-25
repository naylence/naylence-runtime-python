from typing import Optional, Protocol, runtime_checkable

from naylence.fame.core import Stickiness


@runtime_checkable
class ReplicaStickinessManager(Protocol):
    def offer(self) -> Optional[Stickiness]: ...

    def accept(self, stickiness: Optional[Stickiness]) -> None: ...
