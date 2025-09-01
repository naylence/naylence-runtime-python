from __future__ import annotations

from typing import List, Optional, Protocol, TypedDict

from naylence.fame.core import FameEnvelopeWith, NodeWelcomeFrame


class HelloOptions(TypedDict, total=False):
    """
    Options for the admission hello request.
    """

    system_id: str  # may be omitted for first-run
    requested_logicals: List[str]
    instance_id: str  # unique instance identifier


class AdmissionClient(Protocol):
    """
    A thin client that implements the “hello → welcome” RPC to the WelcomeService.
    Does *not* carry arbitrary Fame frames or manage connectors—just admission.
    """

    @property
    def has_upstream(self) -> bool:
        return True

    async def hello(
        self,
        system_id: str,
        instance_id: str,
        requested_logicals: Optional[List[str]] = None,
    ) -> FameEnvelopeWith[NodeWelcomeFrame]:
        """
        Sends a NodeHelloFrame to the WelcomeService and returns the NodeWelcomeFrame.

        :param options.system_id: optional existing system identifier
        :param options.requested_logicals: optional list of logicals
        :param options.instance_id: required unique instance identifier
        :returns: Envelope wrapping a NodeWelcomeFrame, including
                  system_id, assigned_path, connection_grants, attach_token, etc.
        :raises: on network error or if the service rejects the hello
        """
        ...

    async def close(self) -> None:
        """
        Close any resources used by the admission client.
        """
        ...
