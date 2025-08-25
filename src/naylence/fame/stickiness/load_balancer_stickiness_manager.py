from typing import Optional, Protocol, Sequence, runtime_checkable

from naylence.fame.core import FameEnvelope, Stickiness


@runtime_checkable
class LoadBalancerStickinessManager(Protocol):
    def negotiate(self, stickiness: Optional[Stickiness]) -> Optional[Stickiness]: ...

    def get_sticky_replica_segment(
        self, envelope: FameEnvelope, segments: Optional[Sequence[str]] = None
    ) -> Optional[str]: ...
