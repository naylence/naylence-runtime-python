from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.crypto.providers.crypto_provider import CryptoProvider
from naylence.fame.security.policy.security_policy import SigningConfig

from .envelope_signer import EnvelopeSigner, EnvelopeSignerConfig, EnvelopeSignerFactory


class EdDSAEnvelopeSignerConfig(EnvelopeSignerConfig):
    """Config specific to the Ed25519 signer."""

    ...


class EdDSAEnvelopeSignerFactory(EnvelopeSignerFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[EdDSAEnvelopeSignerConfig | dict[str, Any]] = None,
        crypto_provider: Optional[CryptoProvider] = None,
        signing_config: Optional[SigningConfig] = None,
        **kwargs: Any,
    ) -> EnvelopeSigner:
        from .eddsa_envelope_signer import EdDSAEnvelopeSigner

        return EdDSAEnvelopeSigner(crypto=crypto_provider, signing_config=signing_config)
