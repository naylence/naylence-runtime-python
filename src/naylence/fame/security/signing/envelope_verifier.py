"""
Base verifier for FameEnvelope security.

Other algorithms (e.g. RSA-PSS, HSM-backed Ed25519, etc.) can plug-in by
sub-classing these ABCs and registering with the application DI container.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional, TypeVar

from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource


class EnvelopeVerifier(ABC):
    """Validate a FameEnvelope previously signed by a `Signer` implementation."""

    @abstractmethod
    async def verify_envelope(
        self,
        envelope: FameEnvelope,
        check_payload: bool = True,
        logical: Optional[str] = None,
    ) -> bool:  # noqa: D401
        """
        Return **True** if the envelope passes verification, otherwise raise
        `ValueError` with a human-readable reason.

        Args:
            envelope: The envelope to verify
            check_payload: Whether to verify payload digest for DataFrames
            logical: Optional logical to validate against certificate

        Returns:
            True if signature is valid and all policy checks pass

        Raises:
            ValueError: If verification fails or policy violations are detected
        """
        raise NotImplementedError


class EnvelopeVerifierConfig(ResourceConfig):
    """Common config fields for all Verifier implementations."""

    type: str = "EnvelopeVerifier"


C = TypeVar("C", bound=EnvelopeVerifierConfig)


class EnvelopeVerifierFactory(ResourceFactory[EnvelopeVerifier, C]):  # pragma: no cover
    """Abstract resource-factory for Verifier objects (pluggable algos)."""

    @classmethod
    async def create_envelope_verifier(
        cls,
        cfg: Optional[C | dict[str, Any]] = None,
        *,
        key_provider=None,
        signing_config=None,
        **kwargs,
    ) -> Optional[EnvelopeVerifier]:
        """Create an EnvelopeVerifier instance based on the provided configuration."""
        if isinstance(cfg, EnvelopeVerifierConfig):
            cfg_dict = cfg.__dict__
        else:
            cfg_dict = cfg
        return await create_default_resource(
            EnvelopeVerifierFactory,
            cfg_dict,
            key_provider=key_provider,
            signing_config=signing_config,
            **kwargs,
        )
