"""
Base signer for FameEnvelope security.

Other algorithms (e.g. RSA-PSS, HSM-backed Ed25519, etc.) can plug-in by
sub-classing these ABCs and registering with the application DI container.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional, TypeVar

from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource


class EnvelopeSigner(ABC):
    """Produce a cryptographic signature and embed it into a FameEnvelope."""

    @abstractmethod
    def sign_envelope(self, envelope: FameEnvelope, *, physical_path: str) -> FameEnvelope:  # noqa: D401,E501
        """Return *the same* envelope instance with `sec.sig` populated."""
        raise NotImplementedError


class EnvelopeSignerConfig(ResourceConfig):
    """Common config fields for all Signer implementations."""

    type: str = "EnvelopeSigner"


C = TypeVar("C", bound=EnvelopeSignerConfig)


class EnvelopeSignerFactory(ResourceFactory[EnvelopeSigner, C]):  # pragma: no cover
    """Abstract resource-factory for Signer objects (pluggable algos)."""

    @classmethod
    async def create_envelope_signer(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        *,
        crypto_provider=None,
        signing_config=None,
        **kwargs,
    ) -> Optional[EnvelopeSigner]:
        """Create an EnvelopeSigner instance based on the provided configuration."""
        if isinstance(cfg, EnvelopeSignerConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(
            EnvelopeSignerFactory,
            cfg_dict,
            crypto_provider=crypto_provider,
            signing_config=signing_config,
            **kwargs,
        )
