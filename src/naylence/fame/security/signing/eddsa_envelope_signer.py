from __future__ import annotations

from typing import Optional

from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader
from naylence.fame.security.crypto.providers.crypto_provider import (
    CryptoProvider,
    get_crypto_provider,
)
from naylence.fame.security.policy.security_policy import SigningConfig
from naylence.fame.security.signing.eddsa_signer_verifier import (
    _canonical_json,
    frame_digest,
    immutable_headers,
)
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.util import require_crypto
from naylence.fame.util import logging
from naylence.fame.util.util import secure_digest, urlsafe_base64_encode

logger = logging.getLogger(__name__)


class EdDSAEnvelopeSigner(EnvelopeSigner):
    """
    Signs a FameEnvelope with a raw Ed25519 signature.

    The crypto provider supplies the private key (PEM) and its corresponding
    key-id (kid). Supports certificate-enabled signing when configured with
    a SigningConfig that enables certificate features.

    Construction is cheap and nothing is cached.
    """

    def __init__(
        self,
        crypto: Optional[CryptoProvider] = None,
        signing_config: Optional[SigningConfig] = None,
    ) -> None:
        self._crypto = crypto or get_crypto_provider()
        self._signing_config = signing_config or SigningConfig()

    # Public API ------------------------------------------------------------- #

    def sign_envelope(self, envelope: FameEnvelope, *, physical_path: str) -> FameEnvelope:  # noqa: D401,E501
        if not envelope.sid:
            raise ValueError(f"Envelope missing sid: {envelope}")

        # For DataFrame, compute and store payload digest before signing
        from naylence.fame.core.protocol.frames import DataFrame

        if isinstance(envelope.frame, DataFrame):
            # Compute payload digest if not already present
            if envelope.frame.pd is None:
                if envelope.frame.payload is None:
                    payload_str = ""
                else:
                    payload_str = _canonical_json(envelope.frame.payload)
                # logger.trace("computed_dataframe_payload_str",
                #              payload=payload_str,
                #              raw_payload=envelope.frame.payload,
                #              raw_payload_type=type(envelope.frame.payload)
                # )
                envelope.frame.pd = secure_digest(payload_str)

        # 1. Compute digest of the frame (for DataFrame this will be payload-only, for others full frame)
        dig = frame_digest(envelope.frame)

        # 2. Canonicalise immutable headers
        imm_hdrs_json = _canonical_json(immutable_headers(envelope))

        # 3. Construct TBS (To-Be-Signed) bytes
        sid = secure_digest(physical_path)
        tbs = sid.encode() + b"\x1f" + imm_hdrs_json.encode() + b"\x1f" + dig.encode()
        # logger.trace(f"Signer: env: {envelope}, sid: {sid}, tbs: {tbs}")

        # 4. Produce signature
        sig_val = self._sign_ed25519(tbs)

        # 5. Embed into envelope.sec.sig
        # Use certificate-enabled key ID if available and policy allows
        kid = self._get_effective_key_id()

        if envelope.sec is None:
            envelope.sec = SecurityHeader()

        envelope.sec.sig = SignatureHeader(
            kid=kid,
            val=sig_val,
        )

        return envelope

    # Internal helpers ------------------------------------------------------- #

    def _get_effective_key_id(self) -> str:
        """
        Get the effective key ID for signing, preferring certificate-enabled key when available.

        Returns:
            Key ID to use for signing - certificate-enabled key if available and policy allows,
            otherwise the regular signing key.
        """
        # Import here to avoid circular imports
        from naylence.fame.security.policy.security_policy import SigningMaterial

        # If using X.509 certificates and crypto provider supports certificates
        if (
            self._signing_config.signing_material == SigningMaterial.X509_CHAIN
            and hasattr(self._crypto, "node_certificate_pem")
            and hasattr(self._crypto, "node_jwk")
        ):
            try:
                # Check if crypto provider has certificate-enabled capabilities
                cert_pem = self._crypto.node_certificate_pem()
                jwk = self._crypto.node_jwk()

                if cert_pem and jwk and "x5c" in jwk:
                    # Certificate is available, use the certificate-enabled key ID
                    return jwk["kid"]
            except (AttributeError, NotImplementedError):
                # Crypto provider doesn't support certificates, fall back to regular key
                pass

        # Fall back to regular signing key
        return self._crypto.signature_key_id

    def _sign_ed25519(self, data: bytes) -> str:
        require_crypto()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = serialization.load_pem_private_key(self._crypto.signing_private_pem.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Only Ed25519 private keys are supported for signing")
        return urlsafe_base64_encode(key.sign(data))
