from __future__ import annotations

from typing import TypeVar

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.node.admission.admission_client import AdmissionClient


class AdmissionConfig(ResourceConfig):
    type: str = "Admission"


C = TypeVar("C", bound=AdmissionConfig)


class AdmissionClientFactory(ResourceFactory[AdmissionClient, C]): ...
