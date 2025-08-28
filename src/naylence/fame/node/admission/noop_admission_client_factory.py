from __future__ import annotations

from typing import Any, Optional

from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)


class NoopNodeAdmissionConfig(AdmissionConfig):
    type: str = "NoopAdmissionClient"


class NoopAdmissionClientFactory(AdmissionClientFactory):
    async def create(
        self,
        config: Optional[NoopNodeAdmissionConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AdmissionClient:
        from naylence.fame.node.admission.noop_admission_client import NoopAdmissionClient

        return NoopAdmissionClient()
