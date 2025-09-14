from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.security_header import SignatureHeader
from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.security.policy.security_policy import SigningConfig
from naylence.fame.security.signing.eddsa_signer_verifier import (
    _canonical_json,
    frame_digest,
    immutable_headers,
)
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier
from naylence.fame.security.util import require_crypto
from naylence.fame.util.util import secure_digest


def _load_public_key_from_jwk(jwk: Dict[str, Any], signing_config: SigningConfig):
    """
    Extract a public key from a JWK.
    • raw Ed25519 keys use `x`, `crv_x`, or `pub`
    • certificate chains use `x5c` (policy-gated)

    Returns:
        Public key, or (public_key, certificate) tuple if x5c is used
    """
    require_crypto()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Certificate handling (if enabled by policy)
    if "x5c" in jwk:
        # Import here to avoid circular imports
        from naylence.fame.security.policy.security_policy import SigningMaterial

        if signing_config.signing_material != SigningMaterial.X509_CHAIN:
            raise ValueError(
                "Certificate keys disabled by node policy - signing_material must be X509_CHAIN"
            )

        # Phase 1: Get public key using cache-friendly approach
        # Use FAME_CA_CERTS env var as the single source of truth
        import os

        from naylence.fame.security.cert.util import (  # type: ignore
            get_certificate_metadata_from_x5c,
            public_key_from_x5c,
        )

        trust_store_pem = os.getenv("FAME_CA_CERTS")
        if not trust_store_pem:
            raise ValueError(
                "FAME_CA_CERTS environment variable must be set to a PEM file containing trusted CA certs."
            )
        public_key = public_key_from_x5c(
            jwk["x5c"],
            enforce_name_constraints=signing_config.validate_cert_name_constraints,
            trust_store_pem=trust_store_pem,
            return_cert=False,
        )

        # Phase 2: Get certificate metadata only if needed for policy validation
        certificate = None
        if signing_config.require_cert_sid_match or signing_config.require_cert_logical_match:
            cert_metadata = get_certificate_metadata_from_x5c(
                jwk["x5c"],
                trust_store_pem=trust_store_pem,
            )
            certificate = cert_metadata["certificate"]

        # Return tuple for compatibility with existing code
        if certificate:
            return (public_key, certificate)
        else:
            return public_key

    # Regular OKP key handling
    x_b64 = jwk.get("x") or jwk.get("crv_x") or jwk.get("pub")
    if not isinstance(x_b64, str):
        raise ValueError("JWK missing public key material")

    raw = base64.urlsafe_b64decode(x_b64 + "=" * (-len(x_b64) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


class EdDSAEnvelopeVerifier(EnvelopeVerifier):
    """
    Verifies FameEnvelope signatures created by `EdDSASigner`.

    Parameters
    ----------
    key_provider:
        Provider for retrieving keys by kid
    signing_config:
        Configuration for signing behavior, including certificate support
    """

    def __init__(
        self,
        key_provider: KeyProvider,
        signing_config: Optional[SigningConfig] = None,
    ) -> None:
        self._key_provider = key_provider
        self._signing_config = signing_config or SigningConfig()

    # Public API ------------------------------------------------------------- #

    async def verify_envelope(
        self,
        envelope: FameEnvelope,
        check_payload: bool = True,
        logical: Optional[str] = None,
    ) -> bool:  # noqa: D401
        """
        Verify envelope signature with optional SID and logical validation.

        Args:
            envelope: The envelope to verify
            check_payload: Whether to verify payload digest for DataFrames
            logical: Optional logical to validate against certificate

        Returns:
            True if signature is valid and all policy checks pass

        Raises:
            ValueError: If verification fails or policy violations are detected
        """
        sig_hdr: Optional[SignatureHeader] = envelope.sec.sig if envelope.sec else None
        if not sig_hdr:
            raise ValueError("Missing envelope.sec.sig header")
        if not sig_hdr.kid:
            raise ValueError("Signature header missing 'kid'")

        jwk = await self._key_provider.get_key(sig_hdr.kid)
        if jwk is None:
            raise ValueError(f"Unknown key id: {sig_hdr.kid}")

        # Validate that this key is meant for signing
        from naylence.fame.security.crypto.jwk_validation import (
            JWKValidationError,
            validate_signing_key,
        )

        try:
            validate_signing_key(jwk)
        except JWKValidationError as e:
            raise ValueError(f"Key {sig_hdr.kid} is not valid for signing: {e}")

        # Handle DataFrame payload digest verification
        from naylence.fame.core.protocol.frames import DataFrame

        if isinstance(envelope.frame, DataFrame):
            if check_payload:
                # For final destination: verify the payload digest matches
                if envelope.frame.pd is None:
                    raise ValueError("DataFrame missing payload digest (pd field)")

                # Recompute payload digest
                if envelope.frame.payload is None:
                    payload_str = ""
                else:
                    payload_str = _canonical_json(envelope.frame.payload)
                actual_payload_digest = secure_digest(payload_str)

                if envelope.frame.pd != actual_payload_digest:
                    raise ValueError("Payload digest mismatch in DataFrame")

                # Use the verified payload digest for signature verification
                trusted_digest = actual_payload_digest
            else:
                # For intermediates: trust the advertised payload digest
                if envelope.frame.pd is None:
                    raise ValueError(
                        "DataFrame missing payload digest (pd field) for intermediate verification"
                    )
                trusted_digest = envelope.frame.pd
        else:
            # For non-DataFrame: compute full frame digest
            # (intermediates and final destination do the same thing)
            trusted_digest = frame_digest(envelope.frame)

        # Re-create TBS bytes
        sid: str = jwk["sid"]  # enforced by contract
        imm_hdrs = _canonical_json(immutable_headers(envelope))
        tbs = sid.encode() + b"\x1f" + imm_hdrs.encode() + b"\x1f" + trusted_digest.encode()

        # logger.trace(f"Verifier: env: {envelope}, sid: {sid}, tbs: {tbs}")

        # Decode signature
        sig_bytes = base64.urlsafe_b64decode(sig_hdr.val + "=" * (-len(sig_hdr.val) % 4))

        # Public-key verify with certificate validation if applicable
        key_result = _load_public_key_from_jwk(jwk, self._signing_config)

        # Handle certificate-based keys with SID and logical validation
        certificate = None
        if isinstance(key_result, tuple):
            # x5c key - we have (public_key, certificate)
            pub_key, certificate = key_result

            # Validate certificate SID matches envelope SID (if policy requires)
            if self._signing_config.require_cert_sid_match:
                if not envelope.sid:
                    raise ValueError("Envelope missing SID field required for certificate validation")

                # TODO: handle this
                from naylence.fame.security.cert.util import sid_from_cert  # type: ignore

                cert_sid = sid_from_cert(certificate)

                if cert_sid != envelope.sid:
                    raise ValueError(
                        f"Certificate SID '{cert_sid}' does not match envelope SID '{envelope.sid}'"
                    )

            # Validate logical address is permitted by certificate (if policy requires)
            if self._signing_config.require_cert_logical_match and logical:
                from naylence.fame.security.cert.util import host_logicals_from_cert  # type: ignore

                permitted_logicals = host_logicals_from_cert(certificate)

                # Check if the logical address matches any permitted logical address
                if logical not in permitted_logicals:
                    raise ValueError(
                        f"Logical address '{logical}' not permitted by certificate. "
                        f"Allowed logicals: {permitted_logicals}"
                    )
        else:
            # Regular JWK key - no certificate validation
            pub_key = key_result

        pub_key.verify(sig_bytes, tbs)  # raises on failure

        return True
