"""
Factory interface for creating CertificateManager implementations.
"""

from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import Field

from naylence.fame.core import SecuritySettings
from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
)
from naylence.fame.security.policy.security_policy import SigningConfig

from .certificate_manager import CertificateManager


class CertificateManagerConfig(ResourceConfig):
    """Base configuration for CertificateManager implementations."""

    type: str = "CertificateManager"
    security_settings: Optional[SecuritySettings] = Field(
        default=None, description="Security settings for certificate management"
    )
    signing: Optional[SigningConfig] = Field(
        default=None, description="Signing configuration for certificate operations"
    )


C = TypeVar("C", bound=CertificateManagerConfig)


class CertificateManagerFactory(ResourceFactory[CertificateManager, C]):
    """Abstract factory for creating CertificateManager instances."""

    @classmethod
    async def create_certificate_manager(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        *,
        security_settings: Optional[SecuritySettings] = None,
        signing: Optional[SigningConfig] = None,
        **kwargs,
    ) -> Optional[CertificateManager]:
        """Create a CertificateManager instance based on the provided configuration."""
        if isinstance(cfg, CertificateManagerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(
            CertificateManagerFactory,
            cfg_dict,
            security_settings=security_settings,
            signing=signing,
            **kwargs,
        )
