"""Envelope signing and verification."""

from .envelope_signer import EnvelopeSigner, EnvelopeSignerConfig, EnvelopeSignerFactory
from .envelope_verifier import (
    EnvelopeVerifier,
    EnvelopeVerifierConfig,
    EnvelopeVerifierFactory,
)

# EdDSA classes are available through their factories to avoid loading heavy cryptography dependencies
# from .eddsa_envelope_signer import EdDSAEnvelopeSigner
# from .eddsa_envelope_verifier import EdDSAEnvelopeVerifier

__all__ = [
    "EnvelopeSigner",
    "EnvelopeSignerConfig",
    "EnvelopeSignerFactory",
    "EnvelopeVerifier",
    "EnvelopeVerifierConfig",
    "EnvelopeVerifierFactory",
    # "EdDSAEnvelopeSigner",  # Available via factory
    # "EdDSAEnvelopeVerifier" # Available via factory
]
