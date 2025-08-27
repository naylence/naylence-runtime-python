from typing import List, Optional

from naylence.fame.core import FameEnvelopeWith, NodeWelcomeFrame
from naylence.fame.node.admission.admission_client import AdmissionClient


class NoopAdmissionClient(AdmissionClient):
    def has_upstream(self) -> bool:
        return False

    async def hello(
        self,
        system_id: str,
        instance_id: str,
        requested_logicals: Optional[List[str]] = None,
    ) -> FameEnvelopeWith[NodeWelcomeFrame]:
        raise NotImplementedError("NoopAdmissionClient does not support hello")

    async def close(self) -> None:
        pass
