from attr import dataclass

from naylence.fame.node.admission.admission_client import AdmissionClient


@dataclass
class Peer:
    # system_id: str
    admission_client: AdmissionClient
