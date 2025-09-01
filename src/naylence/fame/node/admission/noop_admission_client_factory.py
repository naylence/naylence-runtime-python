"""
Configuration and factory for NoopAdmissionClient.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)


class NoopAdmissionConfig(AdmissionConfig):
    """
    Configuration for NoopAdmissionClient.
    """

    type: str = "NoopAdmissionClient"
    system_id: Optional[str] = None
    auto_accept_logicals: bool = True


class NoopAdmissionClientFactory(AdmissionClientFactory):
    """
    Factory for creating NoopAdmissionClient instances.
    """

    def get_resource_type(self) -> str:
        return "noop"

    async def create(
        self,
        config: Optional[NoopAdmissionConfig | NoopAdmissionConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AdmissionClient:
        """
        Create a NoopAdmissionClient instance.

        :param config: Configuration for the no-op admission client (dict or config object)
        :param kwargs: Additional arguments passed to NoopAdmissionClient constructor
        :returns: Configured NoopAdmissionClient instance
        """
        from naylence.fame.node.admission.noop_admission_client import NoopAdmissionClient

        # Handle different config types
        if config is None:
            # Use defaults
            system_id = kwargs.get("system_id")
            auto_accept_logicals = kwargs.get("auto_accept_logicals", True)
        elif isinstance(config, dict):
            # Config as dictionary
            system_id = config.get("system_id", kwargs.get("system_id"))
            auto_accept_logicals = config.get(
                "auto_accept_logicals", kwargs.get("auto_accept_logicals", True)
            )
        else:
            # Config as object
            system_id = getattr(config, "system_id", kwargs.get("system_id"))
            auto_accept_logicals = getattr(
                config, "auto_accept_logicals", kwargs.get("auto_accept_logicals", True)
            )

        return NoopAdmissionClient(
            system_id=system_id,
            auto_accept_logicals=auto_accept_logicals,
        )
