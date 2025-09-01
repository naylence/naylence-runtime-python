"""
Fame Node Admission components.

This package provides admission clients for different environments:
- AdmissionClient: Base protocol for admission clients
- NoopAdmissionClient: No-op client for environments without admission service
- DefaultNodeAttachClient: Default attach client implementation
"""

from .admission_client import AdmissionClient
from .admission_client_factory import AdmissionClientFactory, AdmissionConfig
from .node_attach_client import NodeAttachClient
from .noop_admission_client import NoopAdmissionClient
from .noop_admission_client_factory import NoopAdmissionClientFactory, NoopAdmissionConfig

__all__ = [
    "AdmissionClient",
    "AdmissionClientFactory",
    "AdmissionConfig",
    "NoopAdmissionClient",
    "NoopAdmissionClientFactory",
    "NoopAdmissionConfig",
    "NodeAttachClient",
]
