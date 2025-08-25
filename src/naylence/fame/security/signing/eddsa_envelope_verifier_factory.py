from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.security.policy.security_policy import SigningConfig

from .envelope_verifier import (
    EnvelopeVerifier,
    EnvelopeVerifierConfig,
    EnvelopeVerifierFactory,
)


class EdDSAEnvelopeVerifierConfig(EnvelopeVerifierConfig):
    """Config for the Ed25519 verifier."""


class EdDSAEnvelopeVerifierFactory(EnvelopeVerifierFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[EdDSAEnvelopeVerifierConfig | dict[str, Any]] = None,
        key_provider: Optional[KeyProvider] = None,
        signing_config: Optional[SigningConfig] = None,
        **kwargs: Any,
    ) -> EnvelopeVerifier:
        from .eddsa_envelope_verifier import EdDSAEnvelopeVerifier

        assert key_provider, "EdDSAEnvelopeVerifierFactory requires a key_provider"
        assert config, "EdDSAVerifierFactory requires a config with `public_keys`"
        return EdDSAEnvelopeVerifier(key_provider=key_provider, signing_config=signing_config)
